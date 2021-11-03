use std::{collections::HashMap, fs, io, path::Path, string::String};

use fanotify::{
    high_level::{Event, Fanotify, FanotifyMode, FanotifyResponse},
    low_level::FAN_OPEN_EXEC_PERM,
};
use k8s_openapi::api::core::v1;
use nix::poll::{poll, PollFd, PollFlags};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::runtime::Builder;

use crate::{
    bpfstructs::{
        container_policy_level, container_policy_level_POLICY_LEVEL_BASELINE,
        container_policy_level_POLICY_LEVEL_PRIVILEGED,
        container_policy_level_POLICY_LEVEL_RESTRICTED,
    },
    HashError,
};
use lockc_uprobes::{add_container, add_process, delete_container};

// static LABEL_NAMESPACE: &str = "io.kubernetes.pod.namespace";
static LABEL_POLICY_ENFORCE: &str = "pod-security.kubernetes.io/enforce";
// static LABEL_POLICY_AUDIT: &str = "pod-security.kubernetes.io/audit";
// static LABEL_POLICY_WARN: &str = "pod-security.kubernetes.io/warn";

static ANNOTATION_CONTAINERD_LOG_DIRECTORY: &str = "io.kubernetes.cri.sandbox-log-directory";
static ANNOTATION_CONTAINERD_SANDBOX_ID: &str = "io.kubernetes.cri.sandbox-id";

static CMDLINE_DELIMITER: char = '\x00';

enum ContainerType {
    Docker,
    KubernetesContainerd,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mount {
    destination: String,
    r#type: String,
    source: String,
    options: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerConfig {
    mounts: Vec<Mount>,
    annotations: Option<HashMap<String, String>>,
}

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("could not retrieve the runc status")]
    Status(#[from] io::Error),

    #[error("could not parse JSON")]
    Json(#[from] serde_json::Error),
}

fn container_type_data<P: AsRef<std::path::Path>>(
    container_bundle: P,
) -> Result<(ContainerType, std::string::String), ContainerError> {
    let bundle_path = container_bundle.as_ref();
    let config_path = bundle_path.join("config.json");
    let f = fs::File::open(config_path)?;
    let r = io::BufReader::new(f);

    let config: ContainerConfig = serde_json::from_reader(r)?;

    // Kubernetes
    if let Some(annotations) = config.annotations {
        // containerd
        if annotations.contains_key(ANNOTATION_CONTAINERD_LOG_DIRECTORY) {
            // containerd doesn't expose k8s namespaces directly. They have
            // to be parsed from the log directory path, where the first
            // part of the filename is the namespace.
            let log_directory = &annotations[ANNOTATION_CONTAINERD_LOG_DIRECTORY];
            let log_path = std::path::PathBuf::from(log_directory);
            let file_name = log_path.file_name().unwrap().to_str().unwrap();
            let mut splitter = file_name.split('_');
            let namespace = splitter.next().unwrap().to_string();

            return Ok((ContainerType::KubernetesContainerd, namespace));
        // containerd
        } else if annotations.contains_key(ANNOTATION_CONTAINERD_SANDBOX_ID) {
            // When a container is running as a part of a previously created
            // pod, the log directory path has to be retrieved from the
            // sandbox container.
            let sandbox_id = &annotations[ANNOTATION_CONTAINERD_SANDBOX_ID];

            // Go one directory up from the current bundle.
            let mut ancestors = bundle_path.ancestors();
            ancestors.next();
            if let Some(v) = ancestors.next() {
                // Then go to sandbox_id directory (sandbox's bundle).
                let new_bundle = v.join(sandbox_id);
                return container_type_data(new_bundle);
            }
        }
        // TODO(vadorovsky): Support more Kubernetes CRI implementations.
        // They all come with their own annotations, so we will have to
        // handle more keys here.
    }

    // Docker
    for mount in config.mounts {
        let source: Vec<&str> = mount.source.split('/').collect();
        if source.len() > 1 && source[source.len() - 1] == "hostname" {
            let config_v2 = str::replace(&mount.source, "hostname", "config.v2.json");
            return Ok((ContainerType::Docker, config_v2));
        }
    }

    Ok((ContainerType::Unknown, String::from("")))
}

/// Finds the policy for the given Kubernetes namespace. If none, the baseline
/// policy is returned. Otherwise checks the Kubernetes namespace labels.
async fn policy_kubernetes(namespace: String) -> Result<container_policy_level, kube::Error> {
    // Apply the privileged policy for kube-system containers immediately.
    // Otherwise the core k8s components (apiserver, scheduler) won't be able
    // to run.
    // If container has no k8s namespace, apply the baseline policy.
    if namespace.as_str() == "kube-system" {
        return Ok(container_policy_level_POLICY_LEVEL_PRIVILEGED);
    }

    let kubeconfig =
        kube::config::Kubeconfig::read_from(std::path::Path::new("/etc/kubernetes/admin.conf"))?;
    let options = kube::config::KubeConfigOptions::default();
    let config = kube::config::Config::from_custom_kubeconfig(kubeconfig, &options).await?;
    let client = kube::Client::try_from(config)?;

    let namespaces: kube::api::Api<v1::Namespace> = kube::api::Api::all(client);
    let namespace = namespaces.get(&namespace).await?;

    match namespace.metadata.labels {
        Some(v) => match v.get(LABEL_POLICY_ENFORCE) {
            Some(v) => match v.as_str() {
                "restricted" => Ok(container_policy_level_POLICY_LEVEL_RESTRICTED),
                "baseline" => Ok(container_policy_level_POLICY_LEVEL_BASELINE),
                "privileged" => Ok(container_policy_level_POLICY_LEVEL_PRIVILEGED),
                _ => Ok(container_policy_level_POLICY_LEVEL_BASELINE),
            },
            None => Ok(container_policy_level_POLICY_LEVEL_BASELINE),
        },
        None => Ok(container_policy_level_POLICY_LEVEL_BASELINE),
    }
}

#[derive(Error, Debug)]
pub enum PolicyKubernetesSyncError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Kube(#[from] kube::Error),
}

/// Makes the `policy_label_sync` function synchronous. We use it together with
/// poll(2) syscall, which is definitely not meant for multithreaded code.
fn policy_kubernetes_sync(
    namespace: String,
) -> Result<container_policy_level, PolicyKubernetesSyncError> {
    match Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(policy_kubernetes(namespace))
    {
        Ok(p) => Ok(p),
        Err(e) => Err(PolicyKubernetesSyncError::from(e)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mounts {
    mounts: Vec<Mount>,
}

fn policy_docker<P: AsRef<Path>>(
    docker_bundle: P,
) -> Result<container_policy_level, ContainerError> {
    let config_path = docker_bundle.as_ref();
    let f = std::fs::File::open(config_path)?;
    let r = std::io::BufReader::new(f);

    let l: Value = serde_json::from_reader(r)?;

    let x = l["Config"]["Labels"]["org.lockc.policy"].as_str();

    match x {
        Some(x) => match x {
            "restricted" => Ok(crate::bpfstructs::container_policy_level_POLICY_LEVEL_RESTRICTED),
            "baseline" => Ok(crate::bpfstructs::container_policy_level_POLICY_LEVEL_BASELINE),
            "privileged" => Ok(crate::bpfstructs::container_policy_level_POLICY_LEVEL_PRIVILEGED),
            _ => Ok(crate::bpfstructs::container_policy_level_POLICY_LEVEL_BASELINE),
        },
        None => Ok(crate::bpfstructs::container_policy_level_POLICY_LEVEL_BASELINE),
    }
}

/// Types of options (prepositioned by `--`).
enum OptParsingAction {
    /// Option not followed by a positional argument.
    NoPositional,
    /// Option followed by a positional argument we don't want to store.
    Skip,
    /// --bundle option which we want to store.
    Bundle,
}

/// Types of positional arguments.
enum ArgParsingAction {
    /// Argument we don't want to store.
    None,
    /// Container ID which we want to store.
    ContainerId,
}

/// Types of actions performed on the container, defined by a runc subcommand.
enum ContainerAction {
    /// Types we don't explicitly handle, except of registering the process as
    /// containerized.
    Other,
    /// Action of creating the container, when we want to register the new
    /// container.
    Create,
    /// Action of deleting the container, when we want to remove the registered
    /// container.
    Delete,
}

#[derive(Error, Debug)]
pub enum UprobeError {
    #[error("failed to call into uprobe, BPF programs are most likely not running")]
    Call,

    #[error("BPF program error")]
    BPF,

    #[error("unknown error")]
    Unknown,
}

fn check_uprobe_ret(ret: i32) -> Result<(), UprobeError> {
    match ret {
        0 => Ok(()),
        n if n == -libc::EAGAIN => Err(UprobeError::Call),
        n if n == -libc::EINVAL => Err(UprobeError::BPF),
        _ => Err(UprobeError::Unknown),
    }
}

pub struct RuncWatcher {
    fd: Fanotify,
}

#[derive(Error, Debug)]
pub enum HandleRuncEventError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Container(#[from] ContainerError),

    #[error(transparent)]
    Hash(#[from] HashError),

    #[error(transparent)]
    PolicyKubernetes(#[from] PolicyKubernetesSyncError),

    #[error(transparent)]
    Uprobe(#[from] UprobeError),
}

impl RuncWatcher {
    pub fn new() -> Result<Self, io::Error> {
        let fd = Fanotify::new_with_nonblocking(FanotifyMode::CONTENT);
        fd.add_path(FAN_OPEN_EXEC_PERM, "/usr/bin/runc")?;
        fd.add_path(FAN_OPEN_EXEC_PERM, "/usr/sbin/runc")?;

        Ok(RuncWatcher { fd })
    }

    fn handle_runc_event(&self, event: Event) -> Result<(), HandleRuncEventError> {
        println!("{:#?}", event);

        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", event.pid))?;

        let mut opt_parsing_action = OptParsingAction::NoPositional;
        let mut arg_parsing_action = ArgParsingAction::None;
        let mut container_action = ContainerAction::Other;

        let mut container_bundle_o: Option<&str> = None;
        let mut container_id_o: Option<&str> = None;

        for arg in cmdline.split(CMDLINE_DELIMITER) {
            match arg {
                // Options which are followed with a positional arguments we don't
                // want to store.
                "--log" => opt_parsing_action = OptParsingAction::Skip,
                "--log-format" => opt_parsing_action = OptParsingAction::Skip,
                "--pid-file" => opt_parsing_action = OptParsingAction::Skip,
                "--console-socket" => opt_parsing_action = OptParsingAction::Skip,
                "--root" => opt_parsing_action = OptParsingAction::Skip,
                // We want to explicitly store the value of --bundle and --root
                // options.
                "--bundle" => opt_parsing_action = OptParsingAction::Bundle,
                _ => {}
            }
            if arg.starts_with('-') {
                // After handling the option, start parsing the next argument.
                continue;
            }

            match opt_parsing_action {
                OptParsingAction::NoPositional => {}
                OptParsingAction::Skip => {
                    opt_parsing_action = OptParsingAction::NoPositional;
                    continue;
                }
                OptParsingAction::Bundle => {
                    container_bundle_o = Some(<&str>::clone(&arg));
                    opt_parsing_action = OptParsingAction::NoPositional;
                    continue;
                }
            }
            match arg_parsing_action {
                ArgParsingAction::None => {}
                ArgParsingAction::ContainerId => {
                    container_id_o = Some(<&str>::clone(&arg));
                    arg_parsing_action = ArgParsingAction::None;
                    continue;
                }
            }

            match arg {
                "checkpoint" => arg_parsing_action = ArgParsingAction::ContainerId,
                "create" => {
                    arg_parsing_action = ArgParsingAction::ContainerId;
                    container_action = ContainerAction::Create;
                }
                "delete" => {
                    arg_parsing_action = ArgParsingAction::ContainerId;
                    container_action = ContainerAction::Delete;
                }
                "events" => arg_parsing_action = ArgParsingAction::ContainerId,
                "exec" => arg_parsing_action = ArgParsingAction::ContainerId,
                "kill" => arg_parsing_action = ArgParsingAction::ContainerId,
                "pause" => arg_parsing_action = ArgParsingAction::ContainerId,
                "ps" => arg_parsing_action = ArgParsingAction::ContainerId,
                "restore" => arg_parsing_action = ArgParsingAction::ContainerId,
                "resume" => arg_parsing_action = ArgParsingAction::ContainerId,
                "run" => arg_parsing_action = ArgParsingAction::ContainerId,
                "start" => {
                    arg_parsing_action = ArgParsingAction::ContainerId;
                }
                "state" => arg_parsing_action = ArgParsingAction::ContainerId,
                "update" => arg_parsing_action = ArgParsingAction::ContainerId,
                _ => {}
            }
        }

        match container_action {
            ContainerAction::Other => {
                if let Some(v) = container_id_o {
                    let container_key = crate::hash(v)?;

                    let mut ret: i32 = -libc::EAGAIN;
                    add_process(&mut ret as *mut i32, container_key, event.pid);
                    check_uprobe_ret(ret)?;
                }
            }
            ContainerAction::Create => {
                let container_key = crate::hash(container_id_o.unwrap())?;
                let container_bundle = match container_bundle_o {
                    Some(v) => std::path::PathBuf::from(v),
                    None => std::env::current_dir()?,
                };

                // let policy;
                let (container_type, container_data) = container_type_data(container_bundle)?;
                let policy: container_policy_level = match container_type {
                    ContainerType::Docker => policy_docker(container_data)?,
                    ContainerType::KubernetesContainerd => policy_kubernetes_sync(container_data)?,
                    ContainerType::Unknown => container_policy_level_POLICY_LEVEL_BASELINE,
                };

                let mut ret: i32 = -libc::EAGAIN;
                add_container(&mut ret as *mut i32, container_key, event.pid, policy);
                check_uprobe_ret(ret)?;
            }
            ContainerAction::Delete => {
                let container_key = crate::hash(container_id_o.unwrap())?;

                let mut ret: i32 = -libc::EAGAIN;
                delete_container(&mut ret as *mut i32, container_key);
                check_uprobe_ret(ret)?;
            }
        }

        // Let the process execute again
        self.fd.send_response(event.fd, FanotifyResponse::Allow);

        Ok(())
    }

    pub fn work_loop(&self) -> Result<(), HandleRuncEventError> {
        let mut fds = [PollFd::new(self.fd.as_raw_fd(), PollFlags::POLLIN)];
        loop {
            let poll_num = poll(&mut fds, -1).unwrap();
            if poll_num > 0 {
                for event in self.fd.read_event() {
                    self.handle_runc_event(event)?;
                }
            } else {
                eprintln!("poll_num <= 0!");
                break;
            }
        }

        Ok(())
    }
}
