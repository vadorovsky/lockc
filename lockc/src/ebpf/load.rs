use std::path::Path;

use aya::{
    include_bytes_aligned,
    programs::{BtfTracePoint, FExit, Lsm, ProgramError, UProbe},
    Bpf, BpfError, BpfLoader, Btf, BtfError,
};
use thiserror::Error;
// use uprobe_ext::FindSymbolResolverExt;

/// Performs the following BPF-related operations:
/// - loading BPF programs
/// - resizing PID-related BPF maps
/// - pinning BPF maps in BPFFS
/// - pinning BPF programs in BPFFS
/// - attaching BPF programs, creating links
/// - pinning links in BPFFS
///
/// All entities pinned in BPFFS have the dedicated directory signed with a
/// timestamp. The reason behind it is to be able to still keep running
/// previous instances of BPF programs while we are in the process of loading
/// new programs. This is done to ensure that **some** instance of BPF programs
/// is always running and that containers are secured.
///
/// TODO: The concept described above still has one hole - the contents of old
/// BPF maps is not migrated in any way. We need to come up with some sane copy
/// mechanism.
pub fn load_bpf<P: AsRef<Path>>(path_base_r: P) -> Result<Bpf, BpfError> {
    let path_base = path_base_r.as_ref();

    #[cfg(debug_assertions)]
    let data = include_bytes_aligned!("../../../target/bpfel-unknown-none/debug/lockc");
    #[cfg(not(debug_assertions))]
    let data = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/lockc");

    let bpf = BpfLoader::new().map_pin_path(path_base).load(data)?;

    Ok(bpf)
}

#[derive(Error, Debug)]
pub enum LoadProgramsError {
    #[error(transparent)]
    Btf(#[from] BtfError),

    #[error(transparent)]
    Program(#[from] ProgramError),

    #[error("could not load the program")]
    ProgLoad,
}

pub fn attach_programs<P: AsRef<Path>>(
    bpf: &mut Bpf,
    _path_base_r: P,
) -> Result<(), LoadProgramsError> {
    // let path_base = path_base_r.as_ref();

    let btf = Btf::from_sys_fs()?;

    let sched_process_fork: &mut BtfTracePoint = bpf
        .program_mut("sched_process_fork")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    sched_process_fork.load("sched_process_fork", &btf)?;
    sched_process_fork.attach()?;

    let sched_process_exec: &mut BtfTracePoint = bpf
        .program_mut("sched_process_exec")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    sched_process_exec.load("sched_process_exec", &btf)?;
    sched_process_exec.attach()?;

    let sched_process_exit: &mut BtfTracePoint = bpf
        .program_mut("sched_process_exit")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    sched_process_exit.load("sched_process_exit", &btf)?;
    sched_process_exit.attach()?;

    let syslog: &mut Lsm = bpf
        .program_mut("syslog")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    syslog.load("syslog", &btf)?;
    syslog.attach()?;

    // let vfs_mkdir: &mut FExit = bpf
    //     .program_mut("vfs_mkdir")
    //     .ok_or(LoadProgramsError::ProgLoad)?
    //     .try_into()?;
    // vfs_mkdir.load("vfs_mkdir", &btf)?;
    // vfs_mkdir.attach()?;

    // let filename_lookup: &mut FExit = bpf
    //     .program_mut("filename_lookup")
    //     .ok_or(LoadProgramsError::ProgLoad)?
    //     .try_into()?;
    // filename_lookup.load("filename_lookup", &btf)?;
    // filename_lookup.attach()?;

    let sb_mount: &mut Lsm = bpf
        .program_mut("sb_mount")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    sb_mount.load("sb_mount", &btf)?;
    sb_mount.attach()?;

    let add_container: &mut UProbe = bpf
        .program_mut("add_container")
        .ok_or(LoadProgramsError::ProgLoad)?
        .try_into()?;
    add_container.load()?;
    // skel.links.add_container = link_add_container.into();
    add_container.attach_own_addr(false, -1, add_container as &mut ())?;

    Ok(())
}
