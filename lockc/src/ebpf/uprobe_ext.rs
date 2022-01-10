use std::os::unix::raw::pid_t;

use aya::{
    programs::{LinkRef, ProgramError, UProbe},
    sys::{kernel_version, perf_event_open_probe, perf_event_open_trace_point},
};
use thiserror::Error;

use goblin::elf::{Elf, Sym};
use procfs::process::Process;

#[derive(Error, Debug)]
pub enum AttachUprobeAddrError {
    #[error(transparent)]
    Libbpf(#[from] aya::BpfError),

    #[error(transparent)]
    Proc(#[from] procfs::ProcError),

    #[error("failed to find executable region")]
    NotFound,
}

pub struct FindSymbolResolverExt<'a> {
    elf: Elf<'a>,
    // fn attach_own_addr(&mut self, pid: Option<pid_t>, addr: u64) -> Result<LinkRef, ProgramError>
}

impl<'a> FindSymbolResolverExt<'a> for UProbe {
    /// Attaches the program to an address within userspace process' own
    /// address space.
    ///
    /// Attaches the uprobe to the given address defined in the `addr`
    /// argument. If `pid` is not `None`, the program executes only when the target
    /// function is executed by the given `pid`.
    ///
    /// If the program is an `uprobe`, it is attached to the *start* address of the target
    /// function. Instead if the program is an `uretprobe`, it is attached to the return address of
    /// the target function. The function has **not** to be mangled and inlined.
    ///
    /// # Examples
    ///
    /// In a separate crate (let's assume it's a `my-uprobes` crate) in
    /// `lib.rs`:
    ///
    /// ```no_run
    /// #[no_mangle]
    /// #[inline(never)]
    /// pub extern "C" fn my_function(_retp: *mut i32, _val: i32) {}
    /// ```
    ///
    /// Main code:
    ///
    /// ```no_run
    /// # use aya::{Bpf, programs::{ProgramError, UProbe}};
    /// # use std::convert::TryInto;
    /// # #[no_mangle]
    /// # #[inline(never)]
    /// # extern "C" fn my_function(_retp: *mut i32, _val: i32) {}
    /// # #[derive(thiserror::Error, Debug)]
    /// # enum Error {
    /// #     #[error(transparent)]
    /// #     Program(#[from] aya::programs::ProgramError),
    /// #     #[error(transparent)]
    /// #     Bpf(#[from] aya::BpfError),
    /// # }
    /// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
    ///
    /// let program: &mut UProbe = bpf.program_mut("uprobe_my_function").unwrap().try_into()?;
    /// program.load()?;
    /// program.attach_own_addr(None, my_function as *const () as u64)?;
    /// # Ok::<(), Error>(())
    /// ```
    fn attach_own_addr(&mut self, pid: Option<pid_t>, addr: u64) -> Result<LinkRef, ProgramError> {
        let target: &str = "/proc/self/exe";

        let base_addr = get_base_addr()?;
        let offset = addr - base_addr;

        attach(&mut self.data, self.kind, target, offset, pid)
    }
}

pub(crate) fn attach(
    program_data: &mut ProgramData,
    kind: ProbeKind,
    fn_name: &str,
    offset: u64,
    pid: Option<pid_t>,
) -> Result<LinkRef, ProgramError> {
    // https://github.com/torvalds/linux/commit/e12f03d7031a977356e3d7b75a68c2185ff8d155
    // Use debugfs to create probe
    let k_ver = kernel_version().unwrap();
    if k_ver < (4, 17, 0) {
        let (fd, event_alias) = create_as_trace_point(kind, fn_name, offset, pid)?;

        return perf_attach_debugfs(program_data, fd, kind, event_alias);
    };

    let fd = create_as_probe(kind, fn_name, offset, pid)?;

    perf_attach(program_data, fd)
}

/// Find our base load address. We use /proc/self/maps for this.
fn get_base_addr() -> Result<usize, AttachUprobeAddrError> {
    let me = Process::myself()?;
    let maps = me.maps()?;

    for entry in maps {
        if entry.perms.contains("r-xp") {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }

    Err(AttachUprobeAddrError::NotFound)
}
