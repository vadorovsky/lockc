use std::{env, path, thread};

use aya_log::BpfLogger;
use eyre::Result;
use log::{debug, error};
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use thiserror::Error;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, oneshot},
};

mod common_ext;
mod communication;
mod ebpf;
mod runc;
mod settings;
mod sysutils;
mod utils;

use communication::EbpfCommand;
use ebpf::{
    load::{attach_programs, load_bpf},
    maps::{add_container, add_lockc, add_process, delete_container, init_allowed_paths},
};
use runc::RuncWatcher;
use sysutils::check_bpf_lsm_enabled;

#[derive(Error, Debug)]
enum FanotifyError {
    #[error("could not send the message")]
    Send,
}

// Runs an fanotify-based runc watcher, which registers containers every time
// they are created or deleted.
fn fanotify(
    fanotify_bootstrap_rx: oneshot::Receiver<()>,
    ebpf_tx: mpsc::Sender<EbpfCommand>,
) -> Result<()> {
    RuncWatcher::new(fanotify_bootstrap_rx, ebpf_tx)?.work_loop()?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum UprobeError {
    #[error("lmao failed to call into uprobe, BPF programs are most likely not running")]
    Call,

    #[error("lmao BPF program error")]
    BPF,

    #[error("lmao unknown uprobe error")]
    Unknown,
}

// Loads and attaches eBPF programs, then fetches logs and events from them.
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

    let mut bpf = load_bpf(path_base.clone())?;

    BpfLogger::init(&mut bpf)?;

    add_lockc(&mut bpf)?;
    debug!("lockc added");
    init_allowed_paths(&mut bpf)?;
    debug!("allowed paths initialized");
    attach_programs(&mut bpf, path_base)?;
    debug!("attached programs");
    // register_allowed_paths()?;

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
                    Ok(_) => {},
                    Err(e) => error!("could not send a response for add_container eBPF command to fanotify thread {:?}", e),
                }
            }
            EbpfCommand::DeleteContainer {
                container_id,
                responder_tx,
            } => {
                let res = delete_container(&mut bpf, container_id);
                match responder_tx.send(res) {
                    Ok(_) => {},
                    Err(e) => error!("could not send a response for delete_container eBPF command to fanotify thread {:?}", e),
                }
            }
            EbpfCommand::AddProcess {
                container_id,
                pid,
                responder_tx,
            } => {
                let res = add_process(&mut bpf, container_id, pid);
                match responder_tx.send(res) {
                    Ok(_) => {},
                    Err(e) => error!("could not send a response for add_process eBPF command to fanotify thread {:?}", e),
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let log_level = match env::var("LOCKC_DEBUG") {
        Ok(_) => LevelFilter::Debug,
        Err(_) => LevelFilter::Info,
    };
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(log_level)
            .set_location_level(log_level)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

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
    let (ebpf_tx, ebpf_rx) = mpsc::channel::<EbpfCommand>(32);

    // Start the thread (but it's going to wait for bootstrap).
    let fanotify_thread = thread::spawn(move || fanotify(fanotify_bootstrap_rx, ebpf_tx));

    // Step 2: Setup a Tokio runtime for asynchronous part of lockc, which#
    // takes care of:
    // * loading and attaching of eBPF programs
    // * fetching events/logs from eBPF programs
    // After initializing the eBPF world, the thread from the step 1 is going
    // to be bootstraped.

    let rt = Runtime::new()?;

    rt.block_on(ebpf(fanotify_bootstrap_tx, ebpf_rx))?;

    // TODO(vadorovsky): Can we somehow just do `?` here, without that
    // stupid wrapping and logging?
    if let Err(e) = fanotify_thread.join() {
        error!("failed to join the fanotify thread: {:?}", e);
    }

    Ok(())
}
