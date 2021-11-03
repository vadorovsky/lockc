//! Extensions for libbpf-rs uprobe functionality. Specifically, we add a higher level
//! interface for resolving symbols from ELF binaries for uprobe attachment as well as
//! attaching uprobes to a function address in our current address space.
//!
//! Based on a similar module in bpfcontain-rs:
//! https://github.com/willfindlay/bpfcontain-rs/blob/ba4fde80b6bc75ef340dd22ac921206b18e350ab/src/uprobe_ext.rs

use std::{fs::read, io, path::Path};

use goblin::elf::{Elf, Sym};
use thiserror::Error;

/// Resolves symbols from an ELF file
/// Based on https://github.com/ingraind/redbpf/blob/main/redbpf/src/symbols.rs
struct SymbolResolver<'a> {
    elf: Elf<'a>,
}

#[derive(Error, Debug)]
pub enum FindInFileError {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Goblin(#[from] goblin::error::Error),

    #[error("failed to find symbol")]
    NotFound,
}

impl<'a> SymbolResolver<'a> {
    /// Find a symbol offset within a file specified by `pathname`
    pub fn find_in_file(pathname: &Path, symbol: &str) -> Result<usize, FindInFileError> {
        let bytes = read(pathname)?;
        let resolver = Self::parse(&bytes)?;
        let offset = resolver.find_offset(symbol);
        match offset {
            Some(o) => Ok(o),
            None => Err(FindInFileError::NotFound),
        }
    }

    /// Parse an ELF file and return a [`SymbolResolver`]
    pub fn parse(bytes: &[u8]) -> Result<SymbolResolver, goblin::error::Error> {
        let elf = Elf::parse(bytes)?;
        Ok(SymbolResolver { elf })
    }

    /// Resolve a symbol in the ELF file
    fn resolve_sym(&self, symbol: &str) -> Option<Sym> {
        self.elf.syms.iter().find(|sym| {
            self.elf
                .strtab
                .get_at(sym.st_name)
                .map(|sym| sym == symbol)
                .unwrap_or(false)
        })
    }

    /// Find the offset of a symbol in the ELF file
    pub fn find_offset(&self, symbol: &str) -> Option<usize> {
        self.resolve_sym(symbol).map(|sym| sym.st_value as usize)
    }
}

#[derive(Error, Debug)]
pub enum AttachUprobeSymbolError {
    #[error(transparent)]
    Libbpf(#[from] libbpf_rs::Error),

    #[error(transparent)]
    FindInFile(#[from] FindInFileError),
}

pub trait FindSymbolUprobeExt {
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link, AttachUprobeSymbolError>;
}

impl FindSymbolUprobeExt for libbpf_rs::Program {
    /// Attach a uprobe to a symbol within another binary.
    fn attach_uprobe_symbol(
        &mut self,
        retprobe: bool,
        pid: i32,
        pathname: &Path,
        symbol: &str,
    ) -> Result<libbpf_rs::Link, AttachUprobeSymbolError> {
        // Find symbol in the ELF file
        let offset = SymbolResolver::find_in_file(pathname, symbol)?;

        // Use the offset we found to attach the probe
        match self.attach_uprobe(retprobe, pid, pathname, offset) {
            Ok(link) => Ok(link),
            Err(e) => Err(AttachUprobeSymbolError::from(e)),
        }
    }
}
