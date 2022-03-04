#![no_std]
#![no_main]

use aya_bpf::{macros::btf_tracepoint, programs::BtfTracePointContext};

mod maps;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use lockc_common::Process;
use maps::*;
use vmlinux::task_struct;

/// Monitors all new tasks/functions created in the system and checks whether
/// it's a child of some already containerized process (either the container
/// runtime or any of its children)
/// In any other case, it does not do anything.
///
/// # Arguments
///
/// * `ppid` - PID of the parent task
/// * `child` - PID of the new task
#[inline]
unsafe fn handle_new_process(_ctx: BtfTracePointContext, ppid: i32, pid: i32) -> Result<i32, i32> {
    // info!(&ctx, "new process");
    let parent_o = PROCESSES.get(&ppid);

    // Check if parent process is containerized (already registered in BPF map).
    // If not, don't do anything.
    if let Some(parent) = parent_o {
        // info!(&ctx, "found parent containerized process");
        // Check if child process is already registered. If yes, don't do
        // anything.
        let child_lookup = PROCESSES.get(&pid);
        if child_lookup.is_some() {
            return Ok(0);
        }

        // // Register a new process.
        // info!(&ctx, "new containerized process");
        let container_id = parent.container_id;
        let child = Process { container_id };
        PROCESSES.insert(&pid, &child, 0).map_err(|e| e as i32)?;
    }

    Ok(0)
}

#[btf_tracepoint(name = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_fork(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let parent_task: *const task_struct = ctx.arg(0);
    let child_task: *const task_struct = ctx.arg(1);

    let ppid = (*parent_task).pid;
    let pid = (*child_task).pid;

    handle_new_process(ctx, ppid, pid)
}

#[btf_tracepoint(name = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sched_process_exec(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let task: *const task_struct = ctx.arg(0);

    let ppid = (*(*task).parent).pid;
    let pid = (*task).pid;

    handle_new_process(ctx, ppid, pid)
}

#[btf_tracepoint(name = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sched_process_exit(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let task: *const task_struct = ctx.arg(0);

    let pid = (*task).pid;

    PROCESSES.remove(&pid).map_err(|e| e as i32)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
