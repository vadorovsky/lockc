#![no_std]
#![no_main]

mod maps;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    cty::c_char,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel_str, bpf_probe_read_str},
    macros::{btf_tracepoint, fexit, lsm, uprobe},
    programs::{BtfTracePointContext, FExitContext, LsmContext, ProbeContext},
};
use aya_log_ebpf::info;

use lockc_common::{
    AccessedPath, Container, ContainerPolicyLevel, InodeId, InodeInfo, Process, MOUNT_TYPE_LEN,
    PATH_LEN,
};
// use lockc_common::{Container, Process, PID_MAX_LIMIT};
use maps::*;
use vmlinux::{dentry, filename, inode, path, task_struct};

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
unsafe fn handle_new_process(ctx: BtfTracePointContext, ppid: i32, pid: i32) -> Result<i32, i32> {
    // info!(&ctx, "new process");
    let parent_o = PROCESSES.get(&ppid);

    // Check if parent process is containerized (already registeed in BPF map).
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

/// Looks up for the policy level for the given process.
/// Returns corresponding policy level (or NotFound when the proceess is not
/// containerized, or LookupErr when the state of BPF maps is inconsistent).
///
/// TODO(vadorovsky): Think of some better way to handle the lookup error - if
/// we ever encounter it, it means that the container/process registration went
/// wrong and we have insonsistent data in BPF maps. Maybe we should somehow
/// try to correct them? Or treat them as a fatal bug in lockc, so then we
/// should inform users about that in logs?
///
/// # Arguments
/// * `pid` - PID of the process to find the policy for
#[inline]
unsafe fn get_policy_level(ctx: LsmContext) -> Result<ContainerPolicyLevel, i32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    // let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    // info!(&ctx, "looking up for pid {}", pid as i32);
    let process_o = PROCESSES.get(&(pid as i32));
    match process_o {
        Some(process) => {
            info!(&ctx, "found process");
            let container_o = CONTAINERS.get(&process.container_id);
            match container_o {
                Some(container) => {
                    info!(&ctx, "found container");
                    Ok(container.policy_level)
                }
                None => Err(-2),
            }
        }
        None => {
            info!(&ctx, "process not found");
            // let p = Process { container_id: 0 };
            // PROCESSES
            //     .insert(&(pid as i32), &p, 0)
            //     .map_err(|err| err as i32)?;
            Ok(ContainerPolicyLevel::NotFound)
        }
    }
}

unsafe fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let parent_task: *const task_struct = ctx.arg(0);
    let child_task: *const task_struct = ctx.arg(1);

    let ppid = (*parent_task).pid;
    let pid = (*child_task).pid;

    // let ppid = 2;
    // let pid = 2;

    handle_new_process(ctx, ppid, pid)
    // Ok(0)
}

#[btf_tracepoint(name = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_fork(ctx) } {
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

#[btf_tracepoint(name = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_exec(ctx) } {
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

#[btf_tracepoint(name = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> i32 {
    match unsafe { try_sched_process_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// unsafe fn try_task_alloc(ctx: LsmContext) -> Result<i32, i32> {
//     let task: *const task_struct = ctx.arg(0);
//     let _clone_flags: c_ulong = ctx.arg(1);
//     let retval: c_int = ctx.arg(2);
//
//     let ppid = (*(*task).parent).pid;
//     let pid = (*task).pid;
//
//     if retval != 0 {
//         return Ok(retval);
//     }
//
//     handle_new_process(ctx, ppid, pid)
// }
//
// /// LSM program triggered by clone().
// #[lsm(name = "task_alloc")]
// pub fn task_alloc(ctx: LsmContext) -> i32 {
//     match unsafe { try_task_alloc(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

unsafe fn try_syslog(ctx: LsmContext) -> Result<i32, i32> {
    // info!(&ctx, "trying syslog");
    match get_policy_level(ctx)? {
        ContainerPolicyLevel::NotFound | ContainerPolicyLevel::Lockc => Ok(0),
        ContainerPolicyLevel::Restricted | ContainerPolicyLevel::Baseline => {
            // info!(&ctx, "syslog: deny");
            Err(-1)
        }
        ContainerPolicyLevel::Privileged => Ok(0),
    }
}

/// LSM program trigerred by attemps to access the kernel logs.
/// Behavior based on policy levels:
/// * restricted: deny
/// * baseline: deny
/// * privileged: allow
#[lsm(name = "syslog")]
pub fn syslog(ctx: LsmContext) -> i32 {
    match unsafe { try_syslog(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// unsafe fn try_vfs_mkdir(ctx: FExitContext) -> Result<i32, i32> {
//     info!(&ctx, "mkdir");
//
//     let parent: *const inode = ctx.arg(2);
//     let new: *const dentry = ctx.arg(3);
//
//     let parent_i_ino: u64 = (*parent).i_ino;
//     info!(&ctx, "parent ino {}", parent_i_ino as u32);
//     let parent_i_rdev: u32 = (*parent).i_rdev;
//     info!(&ctx, "parent rdev {}", parent_i_rdev as u32);
//     let parent_inode_id = InodeId {
//         i_ino: parent_i_ino,
//         i_rdev: parent_i_rdev as u64,
//     };
//     match INODES.get(&parent_inode_id) {
//         Some(p) => {
//             info!(&ctx, "found a parent");
//             let i_ino: u64 = (*(*new).d_inode).i_ino;
//             let i_rdev: u32 = (*(*new).d_inode).i_rdev;
//             let inode_id = InodeId {
//                 i_ino,
//                 i_rdev: i_rdev as u64,
//             };
//             let inode_info = InodeInfo {
//                 parent: parent_inode_id,
//                 permission: p.permission,
//             };
//             // INODES.insert(&inode_id, &inode_info, 0);
//             Ok(0)
//         }
//         None => Ok(0),
//     }
//
//     // Ok(0)
// }
//
// #[fexit(name = "vfs_mkdir")]
// pub fn vfs_mkdir(ctx: FExitContext) -> i32 {
//     match unsafe { try_vfs_mkdir(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// unsafe fn try_filename_lookup(ctx: FExitContext) -> Result<i32, i32> {
//     let p: *const path = ctx.arg(3);
//
//     let i_ino: u64 = (*(*(*p).dentry).d_inode).i_ino;
//     let i_rdev: u32 = (*(*(*p).dentry).d_inode).i_rdev;
//     let parent_i_ino: u64 = (*(*(*(*p).dentry).d_parent).d_inode).i_ino;
//     let parent_i_rdev: u32 = (*(*(*(*p).dentry).d_parent).d_inode).i_rdev;
//     let parent_inode_id = InodeId {
//         i_ino: parent_i_ino,
//         i_rdev: parent_i_rdev as u64,
//     };
//
//     match INODES.get(&parent_inode_id) {
//         Some(p) => {
//             let inode_id = InodeId {
//                 i_ino,
//                 i_rdev: i_rdev as u64,
//             };
//             let inode_info = InodeInfo {
//                 parent: parent_inode_id,
//                 permission: p.permission,
//             };
//             // INODES.insert(&inode_id, &inode_info, 0);
//
//             Ok(0)
//         }
//         None => Ok(0),
//     }
// }
//
// #[fexit(name = "filename_lookup")]
// pub fn filename_lookup(ctx: FExitContext) -> i32 {
//     match unsafe { try_filename_lookup(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

#[derive(Copy, Clone)]
#[repr(C)]
struct CheckPathsCtx {
    path: [u8; PATH_LEN],
    found: bool,
}

unsafe fn try_sb_mount(ctx: LsmContext) -> Result<i32, i32> {
    let _dev_name: *const c_char = ctx.arg(0);
    let _dest_path: *const path = ctx.arg(1);
    let mount_type: *const c_char = ctx.arg(2);

    // Ok(0)
    match get_policy_level(ctx)? {
        // ContainerPolicyLevel::NotFound | ContainerPolicyLevel::Lockc => Ok(0),
        ContainerPolicyLevel::NotFound => {
            // info!(&ctx, "policy not found");
            Ok(0)
        }
        ContainerPolicyLevel::Lockc => {
            // info!(&ctx, "policy lockc");
            Ok(0)
        }
        ContainerPolicyLevel::Restricted => {
            // info!(&ctx, "check mount restricted");
            // We care only about bind mounts. So especially if the type is
            // unknown, we should allow the action and assume it has nothing to
            // do with container engine mounts.
            if mount_type.is_null() {
                return Ok(0);
            }

            let mut mount_type_safe = [0u8; MOUNT_TYPE_LEN];
            bpf_probe_read_kernel_str(mount_type as *const _, &mut mount_type_safe)
                .map_err(|e| e as i32)?;

            let mount_type_bind = b"bind";

            if !mount_type_safe
                .iter()
                .zip(mount_type_bind.iter())
                .all(|(a, b)| a == b)
            {
                return Ok(0);
            }

            // info!(&ctx, "is bind mount");

            Ok(0)
        }
        ContainerPolicyLevel::Baseline => {
            // info!(&ctx, "check mount baseline");
            // We care only about bind mounts. So especially if the type is
            // unknown, we should allow the action and assume it has nothing to
            // do with container engine mounts.
            if mount_type.is_null() {
                return Ok(0);
            }

            let mut mount_type_safe = [0u8; MOUNT_TYPE_LEN];
            bpf_probe_read_kernel_str(mount_type as *const _, &mut mount_type_safe)
                .map_err(|e| e as i32)?;

            let mount_type_bind = b"bind";

            if !mount_type_safe
                .iter()
                .zip(mount_type_bind.iter())
                .all(|(a, b)| a == b)
            {
                return Ok(0);
            }

            // info!(&ctx, "is bind mount");

            Ok(0)
        }
        ContainerPolicyLevel::Privileged => {
            // info!(&ctx, "policy privileged");
            Ok(0)
        }
    }
}

#[lsm(name = "sb_mount")]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    match unsafe { try_sb_mount(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_add_container(ctx: ProbeContext) -> Result<i32, i32> {
    Ok(0)
}

#[uprobe(name = "add_container")]
pub fn add_container(ctx: ProbeContext) -> i32 {
    match unsafe { try_add_container(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline]
fn i32_to_policy_level(level: i32) -> Result<ContainerPolicyLevel, i32> {
    match level {
        l if l == ContainerPolicyLevel::Restricted as i32 => Ok(ContainerPolicyLevel::Restricted),
        l if l == ContainerPolicyLevel::Baseline as i32 => Ok(ContainerPolicyLevel::Baseline),
        l if l == ContainerPolicyLevel::Privileged as i32 => Ok(ContainerPolicyLevel::Privileged),
        _ => Err(1),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
