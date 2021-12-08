/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "limits.h"
#include "policy.h"

struct container {
	enum container_policy_level policy_level;
};

struct process {
	unsigned int container_id;
};

struct accessed_path {
	unsigned char path[PATH_LEN];
};

struct inode_full_info {
	unsigned long i_ino;
	unsigned int i_rdev;
	unsigned long parent_i_ino;
	unsigned int parent_i_rdev;
};

struct inode_info {
	unsigned long i_ino;
	unsigned int i_rdev;
};
