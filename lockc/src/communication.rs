use tokio::sync::oneshot;

use lockc_common::ContainerPolicyLevel;

/// Set of commands that the fanotify thread can send to the eBPF thread
/// to request eBPF map operations.
#[derive(Debug)]
pub enum EbpfCommand {
    AddContainer {
        container_id: String,
        pid: i32,
        policy_level: ContainerPolicyLevel,
        responder_tx: oneshot::Sender<Result<(), eyre::Error>>,
    },
    DeleteContainer {
        container_id: String,
        responder_tx: oneshot::Sender<Result<(), eyre::Error>>,
    },
    AddProcess {
        container_id: String,
        pid: i32,
        responder_tx: oneshot::Sender<Result<(), eyre::Error>>,
    },
}
