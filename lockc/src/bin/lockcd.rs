use std::{env, path, thread};

use anyhow::Result;
use clap::Parser;
use thiserror::Error;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, oneshot},
};
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

use lockc::{
    communication::EbpfCommand,
    load::{attach_programs, load_bpf},
    maps::{add_container, add_process, delete_container, init_allowed_paths},
    runc::RuncWatcher,
    sysutils::check_bpf_lsm_enabled,
};

#[derive(Error, Debug)]
enum FanotifyError {
    #[error("could not send the message")]
    Send,
}

/// Runs an fanotify-based runc watcher, which registers containers every time
/// they are created or deleted.
fn fanotify(
    fanotify_bootstrap_rx: oneshot::Receiver<()>,
    ebpf_tx: mpsc::Sender<EbpfCommand>,
    in_k8s_pod: bool,
) -> Result<()> {
    RuncWatcher::new(fanotify_bootstrap_rx, ebpf_tx, in_k8s_pod)?.work_loop()?;
    Ok(())
}

/// Loads and attaches eBPF programs, then fetches logs and events from them.
async fn ebpf(
    fanotify_bootstrap_tx: oneshot::Sender<()>,
    mut ebpf_rx: mpsc::Receiver<EbpfCommand>,
) -> Result<()> {
    // Check whether BPF LSM is enabled in the kernel. That check should be
    // omitted in Kubernetes (where lockc runs in a container) or nested
    // containers, because sysctls inside containers might hide the fact
    // that BPF LSM is enabled.
    if env::var("LOCKC_CHECK_LSM_SKIP").is_err() {
        let sys_lsm_path = path::Path::new("/sys")
            .join("kernel")
            .join("security")
            .join("lsm");
        check_bpf_lsm_enabled(sys_lsm_path)?;
    }

    let path_base = std::path::Path::new("/sys")
        .join("fs")
        .join("bpf")
        .join("lockc");

    std::fs::create_dir_all(&path_base)?;

    let mut bpf = load_bpf(&path_base)?;

    init_allowed_paths(&mut bpf)?;
    debug!("allowed paths initialized");
    attach_programs(&mut bpf)?;
    debug!("attached programs");

    // Bootstrap the fanotify thread.
    fanotify_bootstrap_tx
        .send(())
        .map_err(|_| FanotifyError::Send)?;

    while let Some(cmd) = ebpf_rx.recv().await {
        match cmd {
            EbpfCommand::AddContainer {
                container_id,
                pid,
                policy_level,
                responder_tx,
            } => {
                let res = add_container(&mut bpf, container_id, pid, policy_level);
                match responder_tx.send(res) {
                    Ok(_) => {}
                    Err(res2) => match res2 {
                        Ok(_) => error!(
                            command = "add_container",
                            "could not send eBPF command result although the operation was succeessful"
                        ),
                        Err(e) => error!(
                            error = e.to_string().as_str(),
                            command = "add_container",
                            "could not execute eBPF command"
                        ),
                    },
                }
            }
            EbpfCommand::DeleteContainer {
                container_id,
                responder_tx,
            } => {
                let res = delete_container(&mut bpf, container_id);
                match responder_tx.send(res) {
                    Ok(_) => {}
                    Err(res2) => match res2 {
                        Ok(_) => error!(
                            command = "delete_container",
                            "could not send eBPF command result although the operation was succeessful"
                        ),
                        Err(e) => error!(
                            error = e.to_string().as_str(),
                            command = "delete_container",
                            "could not execute eBPF command"
                        ),
                    },
                }
            }
            EbpfCommand::AddProcess {
                container_id,
                pid,
                responder_tx,
            } => {
                let res = add_process(&mut bpf, container_id, pid);
                match responder_tx.send(res) {
                    Ok(_) => error!(
                        command = "add_proceess",
                        "could not send eBPF command result although the operation was succeessful"
                    ),
                    Err(res2) => match res2 {
                        Ok(_) => {}
                        Err(e) => error!(
                            error = e.to_string().as_str(),
                            command = "add_process",
                            "could not execute eBPF command"
                        ),
                    },
                }
            }
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(
        long,
        env = "LOCKC_LOG_LEVEL",
        default_value = "info",
        env = "foo",
        possible_values = &["trace", "debug", "info", "warn", "error"]
    )]
    log_level: String,

    #[clap(
        long,
        env = "LOCKC_LOG_FMT",
        default_value = "text",
        possible_values = &["json", "text"]
    )]
    log_fmt: String,

    #[clap(long, env = "LOCKC_IN_K8S_POD")]
    in_k8s_pod: bool,

    #[clap(long, env = "LOCKC_CHECK_LSM_SKIP")]
    skip_lsm_check: bool,
}

#[derive(Error, Debug)]
enum SetupTracingError {
    #[error(transparent)]
    SetGlobalDefault(#[from] tracing_core::dispatcher::SetGlobalDefaultError),

    #[error("unknown log level")]
    UnknownLogLevel,

    #[error("unknown log message format")]
    UnknownLogFormat,
}

fn setup_tracing(matches: &Args) -> Result<(), SetupTracingError> {
    let level = match matches.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => return Err(SetupTracingError::UnknownLogLevel),
    };

    let builder = FmtSubscriber::builder().with_max_level(level);
    match matches.log_fmt.as_str() {
        "json" => {
            let subscriber = builder.json().finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        "text" => {
            let subscriber = builder.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        _ => return Err(SetupTracingError::UnknownLogFormat),
    };

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    setup_tracing(&args)?;

    // Step 1: Create a synchronous thread which takes care of fanotify
    // polling on runc binaries. We monitor all possible runc binaries to get
    // all runc execution events (and therefore - all operations on
    // containers).
    // This thread has to be synchronous and cannot be a part of Tokio runtime,
    // because it:
    // * uses the poll() function
    // * blocks the filesystem operations on monitored files
    // * in case of monitoring runc, we have to be sure that we register a new
    //   container exactly before we allow runc to be actually executed;
    //   otherwise we cannot guarantee that lockc will actually enforce
    //   anything on that container.

    // Fanotify thread bootstrap channel - used later to start the real bootstrap
    // of the thread. We want to bootstrap it later, after loading eBPF
    // programs (which happens in async code in Tokio runtime).
    let (fanotify_bootstrap_tx, fanotify_bootstrap_rx) = oneshot::channel::<()>();

    // eBPF thread channel - used by fanotify thread to request eBFP operations
    // from the async eBPF thread.
    let (ebpf_tx, ebpf_rx) = mpsc::channel::<EbpfCommand>(100);

    // Start the thread (but it's going to wait for bootstrap).
    let fanotify_thread =
        thread::spawn(move || fanotify(fanotify_bootstrap_rx, ebpf_tx, args.in_k8s_pod));

    // Step 2: Setup a Tokio runtime for asynchronous part of lockc, which
    // takes care of:
    // * loading and attaching of eBPF programs
    // * fetching events/logs from eBPF programs
    // After initializing the eBPF world, the thread from the step 1 is going
    // to be bootstraped.

    let rt = Runtime::new()?;

    rt.block_on(ebpf(fanotify_bootstrap_tx, ebpf_rx))?;

    if let Err(e) = fanotify_thread.join() {
        error!("failed to join the fanotify thread: {:?}", e);
    }

    Ok(())
}
