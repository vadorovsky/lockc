extern crate bindgen;

use std::{
    env::{self, consts::ARCH}, fs,
    io::{self, BufRead, Write},
    path, process,
    string::String,
};

use anyhow::{Context, Result};

static CLANG_DEFAULT: &str = "/usr/bin/clang";
static HEADER_MAP_STRUCTS: &str = "src/bpf/map_structs.h";
static VMLINUX_URL: &str =
    "https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/master/vmlinux/vmlinux_508.h";

/// Downloads vmlinux.h from github if it can't be generated.
fn download_btf(mut f: fs::File) -> Result<()> {
    let mut res = reqwest::blocking::get(VMLINUX_URL)?;
    io::copy(&mut res, &mut f)?;

    Ok(())
}

fn generate_btf<P: AsRef<path::Path>>(out_path: P) -> Result<()> {
    let vmlinux_path = out_path.as_ref().join("vmlinux.h");
    let mut f = fs::File::create(vmlinux_path)?;
    match process::Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg("/sys/kernel/btf/vmlinux")
        .arg("format")
        .arg("c")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                f.write_all(&output.stdout)?;
            } else {
                download_btf(f)?;
            }
        }
        Err(_) => download_btf(f)?,
    };

    Ok(())
}

fn build_c_bpf_programs<P: AsRef<path::Path>>(out_path: P) -> Result<()> {
    let arch = match ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        _ => ARCH,
    };
    let clang = match env::var("CLANG") {
        Ok(val) => val,
        Err(_) => String::from(CLANG_DEFAULT),
    };
    let source = path::Path::new("src").join("bpf").join("lockc.bpf.c");

    let mut cmd = process::Command::new(clang);
    cmd
        .arg(format!("-I{}", out_path.as_ref().display()))
        .arg("-g")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .arg(source.as_os_str())
        .arg("-o")
        .arg(out_path.as_ref().join("lockc.bpf.o"))
        .output().context("Failed to execute clang")?;

    Ok(())
}

fn generate_bindings<P: AsRef<path::Path>>(out_path: P) -> Result<()> {
    println!("cargo:rerun-if-changed={}", HEADER_MAP_STRUCTS);

    let bindings = bindgen::Builder::default()
        .header(HEADER_MAP_STRUCTS)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap();

    bindings.write_to_file(out_path.as_ref().join("bindings.rs"))?;

    Ok(())
}

fn main() -> Result<()> {
    let out_path = path::PathBuf::from(env::var("OUT_DIR")?);

    generate_btf(out_path.clone())?;
    build_c_bpf_programs(out_path.clone())?;
    generate_bindings(out_path)?;

    Ok(())
}
