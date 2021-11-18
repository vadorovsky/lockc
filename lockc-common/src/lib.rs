#![no_std]

use bitflags::bitflags;

/// Max configurable PID limit (for x86_64, for the other architectures it's
/// less or equal).
// TODO(vadorovsky): I need to teach aya to be able to resize maps before they
// are loaded into the kernel. So far aya doesn't differentiate between open()
// and load(), it opens the ELF object and loads it imediatelly in one step.
// I need to change it.
// After that, we will be able to set the limit again up to the upper possible
// limit. And resize according to the max PID limit in sysctl.
// Before it's done - let's stick to the default value to not use too much RAM.
// pub const PID_MAX_LIMIT: u32 = 4194304;
pub const PID_MAX_LIMIT: u32 = 32768;

/// Our arbitrary path length limit.
pub const PATH_LEN: usize = 4096;
// pub const PATH_MAX_LIMIT: u32 = 4096;
pub const PATH_MAX_LIMIT: u32 = 850000;

pub const MOUNT_TYPE_LEN: usize = 5;

#[cfg_attr(feature = "userspace", derive(Debug))]
#[derive(Copy, Clone)]
#[repr(C)]
pub enum ContainerPolicyLevel {
    NotFound = -1,

    Lockc,

    // Policy levels.
    Restricted,
    Baseline,
    Privileged,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Container {
    pub policy_level: ContainerPolicyLevel,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Process {
    pub container_id: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct AccessedPath {
    pub path: [u8; PATH_LEN],
}

bitflags! {
    pub struct FilePermission: u32 {
        const EXEC = 0b0000000000000001;
        const WRITE = 0b0000000000000010;
        const READ = 0b0000000000000100;
        const APPEND = 0b0000000000001000;
        const CHMOD = 0b0000000000010000;
        const DELETE = 0b0000000000100000;
        const EXECMMAP = 0b0000000001000000;
        const LINK = 0b0000000010000000;
        const IOCTL = 0b0000000100000000;
        const MOUNT = 0b0000001000000000;
        const ALL_ACCESS = Self::EXEC.bits |
            Self::WRITE.bits |
            Self::READ.bits |
            Self::APPEND.bits |
            Self::CHMOD.bits |
            Self::DELETE.bits |
            Self::EXECMMAP.bits |
            Self::LINK.bits |
            Self::IOCTL.bits;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct InodeId {
    pub i_ino: u64,
    pub i_rdev: u64,
}

#[derive(Copy, Clone)]
pub struct InodeInfo {
    pub parent: InodeId,
    pub permission: FilePermission,
}

#[cfg(feature = "userspace")]
mod userspace {
    use super::*;

    unsafe impl aya::Pod for Container {}
    unsafe impl aya::Pod for Process {}
    unsafe impl aya::Pod for AccessedPath {}
    unsafe impl aya::Pod for InodeId {}
    unsafe impl aya::Pod for InodeInfo {}
}
