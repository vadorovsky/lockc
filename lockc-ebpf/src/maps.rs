use aya_bpf::{macros::map, maps::HashMap};

use lockc_common::{
    AccessedPath, Container, InodeId, InodeInfo, Process, PATH_MAX_LIMIT, PID_MAX_LIMIT,
};

/// BPF map containing the info about a policy which should be enforced on the
/// given container.
#[map]
pub(crate) static mut CONTAINERS: HashMap<u32, Container> =
    HashMap::with_max_entries(PID_MAX_LIMIT, 0);

/// BPF map which maps the PID to a container it belongs to. The value of this
/// map, which represents the container, is a key of `containers` BPF map, so
/// it can be used immediately for lookups in `containers` map.
#[map]
pub(crate) static mut PROCESSES: HashMap<i32, Process> =
    HashMap::with_max_entries(PID_MAX_LIMIT, 0);

#[map]
pub(crate) static mut PATH_TO_INODE: HashMap<AccessedPath, InodeId> =
    HashMap::with_max_entries(1000, 0);

#[map]
pub(crate) static mut INODES: HashMap<InodeId, InodeInfo> = HashMap::with_max_entries(1000, 0);

/// BPF map which contains the source path prefixes allowed to bind mount from
/// host to restricted containers. It should contain only paths used by default
/// by container runtimes, not paths mounted with the -v option.
#[map]
pub(crate) static mut ALLOWED_PATHS_MOUNT_RESTRICTED: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);

/// BPF map which contains the source path prefixes allowed to bind mount from
/// host to baseline containers. It should contain both paths used by default
/// by container runtimes and paths we allow to mount with -v option.
#[map]
pub(crate) static mut ALLOWED_PATHS_MOUNT_BASELINE: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);

/// BPF map which contains the path prefixes allowed to access (open, create,
/// delete, move etc.) inside filesystems of restricted containers.
#[map]
pub(crate) static mut ALLOWED_PATHS_ACCESS_RESTRICTED: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);

/// BPF map which contains the path prefixes allowed to access (open, create,
/// delete, move etc.) inside filesystems of baseline containers.
#[map]
pub(crate) static mut ALLOWED_PATHS_ACCESS_BASELINE: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);

/// BPF map which contains the path prefixes denied to access (open, create,
/// delete, move etc.) inside filesystems of restricted containers.
#[map]
pub(crate) static mut DENIED_PATHS_ACCESS_RESTRICTED: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);

/// BPF map which contains the path prefixes denied to access (open, create,
/// delete, move etc.) inside filesystems of baseline containers.
#[map]
pub(crate) static mut DENIED_PATHS_ACCESS_BASELINE: HashMap<u32, AccessedPath> =
    HashMap::with_max_entries(PATH_MAX_LIMIT, 0);
