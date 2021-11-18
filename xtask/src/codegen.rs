use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use aya_gen::btf_types;
use eyre::Result;

pub fn generate() -> Result<()> {
    let dir = PathBuf::from("lockc-ebpf/src");
    let names: Vec<&str> = vec!["task_struct"];
    let bindings = btf_types::generate(Path::new("/sys/kernel/btf/vmlinux"), &names, true)?;
    let mut out = File::create(dir.join("vmlinux.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
