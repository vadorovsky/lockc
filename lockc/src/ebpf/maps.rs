use std::{fs, os::unix::fs::MetadataExt, path::Path, process};

use aya::{maps::HashMap, Bpf};
use lazy_static::lazy_static;
use log::debug;
use thiserror::Error;
use walkdir::WalkDir;

use crate::{common_ext::AccessedPathExt, settings, utils::hash};
use lockc_common::{
    AccessedPath, Container, ContainerPolicyLevel, FilePermission, InodeId, InodeInfo, Process,
};

lazy_static! {
    static ref SETTINGS: settings::Settings = settings::Settings::new().unwrap();
}

pub fn add_lockc(bpf: &mut Bpf) -> Result<(), eyre::Error> {
    let mut containers: HashMap<_, u32, Container> = bpf.map_mut("CONTAINERS")?.try_into()?;
    let container_key: u32 = 0;
    let container = Container {
        policy_level: ContainerPolicyLevel::Lockc,
    };
    containers.insert(container_key, container, 0)?;

    let mut processes: HashMap<_, i32, Process> = bpf.map_mut("PROCESSES")?.try_into()?;
    let p = Process {
        container_id: container_key,
    };
    let pid = process::id() as i32;
    processes.insert(pid, p, 0)?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum AllowedPathsError {
    #[error("could not find parent")]
    NoParent,
}

pub fn init_allowed_paths(bpf: &mut Bpf) -> Result<(), eyre::Error> {
    let mut path_to_inode: HashMap<_, AccessedPath, InodeId> =
        bpf.map_mut("PATH_TO_INODE")?.try_into()?;
    let mut inodes: HashMap<_, InodeId, InodeInfo> = bpf.map_mut("INODES")?.try_into()?;

    let mut ii: usize = 0;
    for (i, allowed_path) in SETTINGS.allowed_paths_mount_restricted.iter().enumerate() {
        if Path::new(allowed_path).exists() {
            debug!("initializing path {}", allowed_path);
            for entry_res in WalkDir::new(allowed_path) {
                let entry = entry_res?;
                let cur_path = entry.path();
                if Path::new(cur_path).exists() {
                    debug!(
                        "recursively initializing i {} path {}",
                        ii,
                        cur_path.display()
                    );
                    let cur_path_meta = fs::metadata(cur_path)?;
                    let parent_meta =
                        fs::metadata(cur_path.parent().ok_or(AllowedPathsError::NoParent)?)?;

                    debug!("i_ino: {}", cur_path_meta.ino());
                    debug!("i_rdev: {}", cur_path_meta.rdev());

                    let ap = AccessedPath::new(cur_path)?;
                    let inode_id = InodeId {
                        i_ino: cur_path_meta.ino(),
                        i_rdev: cur_path_meta.rdev(),
                    };
                    let parent_inode_id = InodeId {
                        i_ino: parent_meta.ino(),
                        i_rdev: parent_meta.rdev(),
                    };
                    let inode_info = InodeInfo {
                        parent: parent_inode_id,
                        permission: FilePermission::MOUNT,
                    };

                    path_to_inode.insert(ap, inode_id, 0)?;
                    inodes.insert(inode_id, inode_info, 0)?;
                    ii += 1;
                } else {
                    debug!("path {} does not exist", cur_path.display());
                }
            }
        }
    }

    // let mut mount_baseline: HashMap<_, u32, AccessedPath> =
    //     bpf.map_mut("ALLOWED_PATHS_MOUNT_BASELINE")?.try_into()?;
    // for (i, allowed_path_s) in SETTINGS.allowed_paths_mount_baseline.iter().enumerate() {
    //     let ap = AccessedPath::new(allowed_path_s)?;
    //     mount_baseline.insert(i as u32, ap, 0)?;
    // }

    // let mut access_restricted: HashMap<_, u32, AccessedPath> =
    //     bpf.map_mut("ALLOWED_PATHS_ACCESS_RESTRICTED")?.try_into()?;
    // for (i, allowed_path_s) in SETTINGS.allowed_paths_access_restricted.iter().enumerate() {
    //     let ap = AccessedPath::new(allowed_path_s)?;
    //     access_restricted.insert(i as u32, ap, 0)?;
    // }

    // let mut access_baseline: HashMap<_, u32, AccessedPath> =
    //     bpf.map_mut("ALLOWED_PATHS_ACCESS_BASELINE")?.try_into()?;
    // for (i, allowed_path_s) in SETTINGS.allowed_paths_access_baseline.iter().enumerate() {
    //     let ap = AccessedPath::new(allowed_path_s)?;
    //     access_baseline.insert(i as u32, ap, 0)?;
    // }

    Ok(())
}

pub fn add_container(
    bpf: &mut Bpf,
    container_id: String,
    pid: i32,
    policy_level: ContainerPolicyLevel,
) -> Result<(), eyre::Error> {
    debug!("adding container {} to eBPF map", container_id);

    let mut containers: HashMap<_, u32, Container> = bpf.map_mut("CONTAINNERS")?.try_into()?;
    let container_key = hash(&container_id)?;
    let container = Container { policy_level };
    containers.insert(container_key, container, 0)?;

    let mut processes: HashMap<_, i32, Process> = bpf.map_mut("PROCESSES")?.try_into()?;
    let process = Process {
        container_id: container_key,
    };
    processes.insert(pid, process, 0)?;

    Ok(())
}

pub fn delete_container(bpf: &mut Bpf, container_id: String) -> Result<(), eyre::Error> {
    debug!("deleting container {} from eBPF map", container_id);

    let mut containers: HashMap<_, u32, Container> = bpf.map_mut("CONTAINNERS")?.try_into()?;
    let container_key = hash(&container_id)?;
    containers.remove(&container_key)?;

    let processes: HashMap<_, i32, Process> = bpf.map("PROCESSES")?.try_into()?;
    let mut processes_mut: HashMap<_, i32, Process> = bpf.map_mut("PROCESS")?.try_into()?;
    for res in processes.iter() {
        let (pid, process) = res?;
        if process.container_id == container_key {
            processes_mut.remove(&pid);
        }
    }

    Ok(())
}

pub fn add_process(bpf: &mut Bpf, container_id: String, pid: i32) -> Result<(), eyre::Error> {
    debug!(
        "adding process {} (container: {}) to eBPF map",
        pid, container_id
    );

    let mut processes: HashMap<_, i32, Process> = bpf.map_mut("PROCESSES")?.try_into()?;
    let container_key = hash(&container_id)?;
    let process = Process {
        container_id: container_key,
    };
    processes.insert(pid, process, 0)?;

    Ok(())
}
