use bitflags::bitflags;
use libc::fanotify_init;

bitflags!{
    pub struct FanotifyEvents: u32 {
        /// File was accessed
        const ACCESS = 0x0000_0001;
        /// File was modified
        const MODIFY = 0x0000_0002;
        /// Metadata changed
        const ATTRIB = 0x0000_0004;
        /// Writtable file closed
        const CLOSE_WRITE = 0x0000_0008;
        /// Unwrittable file closed
        const CLOSE_NOWRITE	= 0x0000_0010;
        /// File was opened
        const OPEN = 0x0000_0020;
        /// File was moved from X
        const MOVED_FROM = 0x00000040;
        /// File was moved to Y
        const MOVED_TO = 0x0000_0080:
        /// Subfile was created
        const CREATE = 0x00000100;
        /// Subfile was deleted
        const DELETE = 0x00000200;
        /// Self was deleted
        const DELETE_SELF = 0x00000400;
        /// Self was moved
        const MOVE_SELF	= 0x00000800;
        /// File was opened for exec
        const OPEN_EXEC	= 0x00001000;
        /// Event queued overflowed
        const Q_OVERFLOW = 0x00004000;
        /// Filesystem error
        const FS_ERROR = 0x00008000;
        /// File open in perm check
        const OPEN_PERM	= 0x00010000;
        /// File accessed in perm check
        const ACCESS_PERM = 0x00020000;
        /// File open/exec in perm check
        const OPEN_EXEC_PERM = 0x00040000;
        /// Interested in child events
        const EVENT_ON_CHILD = 0x08000000;
        /// Event occurred against dir
        const ONDIR	= 0x40000000;
        /// Close
        const CLOSE	= Self::CLOSE_WRITE | Self::CLOSE_NOWRITE;
        /// Moves
        const MOVE = Self::MOVED_FROM | Self::MOVED_TO;
    }

    pub struct FanotifyInit: u32 {
        const CLOEXEC = 0x0000_0001;
        const NONBLOCK = 0x0000_0002;
    }

    pub struct FanotifyClass: u32 {
        const NOTIF = 0x0000_0000;
        const CONTENT = 0x0000_0004;
        const PRE_CONTENT = 0x0000_0008;
    }

    pub struct FanotifyFlags: u32 {
        const FAN_UNLIMITED_QUEUE = 0x0000_0010;
        const FAN_UNLIMITED_MARKS = 0x0000_0020;
        const FAN_ENABLE_AUDIT = 0x0000_0040;
    }

    pub struct FanotifyReport: u32 {
        
    }
}

pub struct Fanotify {
    fd: i32,
}

impl Fanotify {
    pub fn new_with_blocking(mode)
}
