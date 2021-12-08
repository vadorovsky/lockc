use std::{env, path, process};

use chrono::prelude::*;
use log::debug;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};

use lockc::bpfstructs::container_policy_level_POLICY_LEVEL_LOCKC;
use lockc_uprobes::add_container;

fn main() -> anyhow::Result<()> {
    let log_level = match env::var("LOCKC_DEBUG") {
        Ok(_) => LevelFilter::Debug,
        Err(_) => LevelFilter::Info,
    };
    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(log_level)
            .set_location_level(log_level)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    if env::var("LOCKC_CHECK_LSM_SKIP").is_err() {
        let sys_lsm_path = path::Path::new("/sys")
            .join("kernel")
            .join("security")
            .join("lsm");
        lockc::check_bpf_lsm_enabled(sys_lsm_path)?;
    }

    let now = Utc::now();
    let dirname = now.format("%s").to_string();
    let path_base = std::path::Path::new("/sys")
        .join("fs")
        .join("bpf")
        .join("lockc");

    std::fs::create_dir_all(&path_base)?;

    let path_base_ts = path_base.join(&dirname);

    let _skel = lockc::BpfContext::new(path_base_ts)?;
    debug!("initialized BPF skeleton, loaded programs");
    lockc::cleanup(path_base, &dirname)?;
    debug!("cleaned up old BPF programs");

    let mut ret: i32 = -libc::EAGAIN;
    add_container(
        &mut ret as *mut i32,
        0,
        process::id() as i32,
        container_policy_level_POLICY_LEVEL_LOCKC,
    );
    lockc::runc::check_uprobe_ret(ret)?;

    lockc::register_allowed_paths()?;

    lockc::runc::RuncWatcher::new()?.work_loop()?;

    Ok(())
}
