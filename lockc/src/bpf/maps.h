/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "map_structs.h"

/*
 * runtimes - BPF map containing the process names of container runtime init
 * processes (for example: `runc:[2:INIT]` which is the name of every init
 * process for runc).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u32);
} runtimes SEC(".maps");

/*
 * containers - BPF map containing the info about a policy which should be
 * enforced on the given container.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct container);
} containers SEC(".maps");

/*
 * processes - BPF map which maps the PID to a container it belongs to. The
 * value of this map, which represents the container, is a key of `containers`
 * BPF map, so it can be used immediately for lookups in `containers` map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PID_MAX_LIMIT);
	__type(key, pid_t);
	__type(value, struct process);
} processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	// __type(key, struct accessed_path);
	__type(key, u32);
	// __type(value, struct inode_full_info);
	__type(value, struct inode_info);
} inodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, struct inode_info);
	__type(value, struct inode_info);
} inodes_parents SEC(".maps");

/*
 * allowed_paths_mount_restricted - BPF map which contains the source path
 * prefixes allowed to bind mount from host to restricted containers. It should
 * contain only paths used by default by container runtimes, not paths mounted
 * with the -v option.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} allowed_paths_mount_restricted SEC(".maps");

/*
 * allowed_paths_mount_baseline - BPF map which contains the source path
 * prefixes allowed to bind mount from host to baseline containers. It
 * should contain both paths used by default by container runtimes and
 * paths we allow to mount with -v option.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} allowed_paths_mount_baseline SEC(".maps");

/*
 * allowed_paths_access_restricted - BPF map which contains the path prefixes
 * allowed to access (open, create, delete, move etc.) inside filesystems of
 * restricted containers.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} allowed_paths_access_restricted SEC(".maps");

/*
 * allowed_paths_access_baseline - BPF map which contains the path prefixes
 * allowed to access (open, create, delete, move etc.) inside filesystems of
 * baseline containers.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} allowed_paths_access_baseline SEC(".maps");

/*
 * denied_paths_access_restricted - BPF map which contains the path prefixes
 * denied to access (open, create, delete, move etc.) inside filesystems of
 * restricted containers.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} denied_paths_access_restricted SEC(".maps");

/*
 * denied_paths_access_baseline - BPF map which contains the path prefixes
 * denied to access (open, create, delete, move etc.) inside filesystems of
 * baseline containers.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PATH_MAX_LIMIT);
	__type(key, u32);
	__type(value, struct accessed_path);
} denied_paths_access_baseline SEC(".maps");
