#![no_std]

pub static PID_MAX_LIMIT: u32 = 4194304;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Process {
    pub container_id: u32,
}
