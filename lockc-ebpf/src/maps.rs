use aya_bpf::{macros::map, maps::HashMap};

use lockc_common::{Process, PID_MAX_LIMIT};

#[map]
pub(crate) static mut PROCESSES: HashMap<i32, Process> = HashMap::pinned(PID_MAX_LIMIT, 0);
