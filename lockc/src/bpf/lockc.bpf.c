/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "compiler.h"
#include "maps.h"
#include "strutils.h"

#ifndef NULL
#define NULL 0
#endif

#define EPERM 1
#define EFAULT 14

/*
 * The `type` pointer coming from the sb_mount LSM hook has allocatted a full
 * page size, but since we are interested only in "bind" mounts, allocating a
 * buffer of size 5 is enough.
 */
#define MOUNT_TYPE_LEN 5
#define MOUNT_TYPE_BIND "bind"

/*
 * get_policy_level - find the policy level for the given process.
 * @pid: the PID of the process to find the policy for
 *
 * Return: corresponding policy level (or POLICY_LEVEL_NOT_FOUND when the
 * process is not containerized, or POLICY_LEVEL_LOOKUP_ERROR when the state
 * of BPF maps is inconsistent).
 *
 * TODO: Think of some better way to handle the POLICY_LEVEL_LOOKUP_ERROR - if
 * that value is ever returned, it means that the container/process
 * registration went wrong and we have insonsistent data.
 */
static __always_inline enum container_policy_level get_policy_level(pid_t pid)
{
	int err;

	struct process *p = bpf_map_lookup_elem(&processes, &pid);
	if (!p) {
		return POLICY_LEVEL_NOT_FOUND;
	}

	struct container *c =
		bpf_map_lookup_elem(&containers, &p->container_id);
	if (!c) {
		/* Shouldn't happen */
		bpf_printk("error: get_policy_level: could not found a "
			   "container for a registered process\n");
		return POLICY_LEVEL_LOOKUP_ERR;
	}

	return c->policy_level;
}

/*
 * BPF programs
 * ============
 */

/*
 * syslog_audit - LSM program trigerred by attemps to access the kernel logs.
 * Behavior based on policy levels:
 * - restricted: deny
 * - baseline: deny
 * - privileged: allow
 */
SEC("lsm/syslog")
int BPF_PROG(syslog_audit, int type, int ret_prev)
{
	int ret = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	enum container_policy_level policy_level = get_policy_level(pid);

	switch (policy_level) {
	case POLICY_LEVEL_LOOKUP_ERR:
		/* Shouldn't happen */
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_NOT_FOUND:
		goto out;
	case POLICY_LEVEL_RESTRICTED:
		bpf_printk("syslog: restricted: deny\n");
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_BASELINE:
		bpf_printk("syslog: baseline: deny\n");
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_PRIVILEGED:
		bpf_printk("syslog: privileged: allow\n");
		goto out;
	}

out:
	/* Handle results of previous programs */
	if (ret_prev != 0) {
		bpf_printk("syslog previous result\n");
		return ret_prev;
	}
	return ret;
}

/*
 * paths_callback_ctx - input/output data for the `check_allowed_paths` callback
 * function.
 */
struct paths_callback_ctx {
	/* Input path to compare all the allowed paths with. */
	unsigned char *path;
	/* Output whether a match was found. */
	bool found;
};

/*
 * check_allowed_paths - callback function which checks whether the given source
 * path (about which we make decision whether to mount it) matches the currently
 * checked allowed path.
 * @map: the BPF map with allowed paths
 * @key: the key of the checked BPF map element
 * @allowed_path: the checked BPF map element
 * @data: input/output data shared between this callback and the BPF program
 *
 * Return: 1 if the match was found and next iterations should be stopped.
 * 0 if the match was not found and the search for a possible match should be
 * continued.
 */
static u64 check_paths(struct bpf_map *map, u32 *key,
		       struct accessed_path *allowed_path,
		       struct paths_callback_ctx *data)
{
	/*
	 * Shouldn't happen, but if in any case the checked path is NULL, skip
	 * it and go to the next element. Comparing it would result in a match
	 * (because of comparing with 0 length).
	 */
	if (unlikely(allowed_path == NULL))
		return 0;

	bpf_printk("checking path: key: %u, dev_name: %s, current: %s\n", *key,
		   data->path, allowed_path->path);

	size_t allowed_path_len = strlen(allowed_path->path, PATH_LEN);

	/*
	 * Shouldn't happen, but if in any case the checked path is empty, skip
	 * it and go to the next element. Comparing it could result in a match
	 * (because of comparing with 0 length).
	 */
	if (unlikely(allowed_path_len < 1))
		return 0;

	if (strcmp(allowed_path->path, data->path, allowed_path_len) == 0) {
		bpf_printk("path check matched\n");
		data->found = true;
		return 1;
	}

	return 0;
}

/*
 * mount_audit - LSM program triggered by any mount attempt. Its goal is to deny
 * the bind mounts to restricted and baseline containers whose source prefixes
 * are not specified as allowed in BPF maps.
 * @dev_name: source path
 * @path: destination path
 * @type: type of mount
 * @flags: mount flags
 * @data: filesystem-specific data
 * @ret_prev: return code of a previous BPF program using the sb_mount hook
 *
 * Return: 0 if mount allowed. -EPERM if mount not allowed. -EFAULT if there was
 * a problem with reading the kernel strings into buffers or any important
 * buffer is NULL.
 */
SEC("lsm/sb_mount")
int BPF_PROG(mount_audit, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret_prev)
{
	int ret = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	enum container_policy_level policy_level = get_policy_level(pid);
	struct path *path_mut = (struct path *)path;
	unsigned char type_bind[MOUNT_TYPE_LEN] = MOUNT_TYPE_BIND;
	unsigned char type_safe[MOUNT_TYPE_LEN];
	unsigned char dev_name_safe[PATH_LEN];

	switch (policy_level) {
	case POLICY_LEVEL_LOOKUP_ERR:
		/* Shouldn't happen */
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_NOT_FOUND:
		goto out;
	case POLICY_LEVEL_RESTRICTED:
		break;
	case POLICY_LEVEL_BASELINE:
		break;
	case POLICY_LEVEL_PRIVILEGED:
		bpf_printk("mount: privileged: allow\n");
		goto out;
	}

	/* Retrieve the mount type. */
	if (unlikely(type == NULL)) {
		/*
		 * TODO(vadorovsky): Investigate the "empty type" mounts more.
		 * Apparently denying them was breaking bwrap and flatpak...
		 */
		bpf_printk("warning: mount type is NULL\n");
		goto out;
	}
	if (unlikely(bpf_probe_read_kernel_str(&type_safe, MOUNT_TYPE_LEN,
					       type) < 0)) {
		bpf_printk("error: could not read the mount type\n");
		ret = -EFAULT;
		goto out;
	}

	/* Apply the policy only on bind mounts. */
	if (strcmp(type_safe, type_bind, MOUNT_TYPE_LEN) != 0)
		goto out;

	/* Check and retrieve the dev_name (source path). */
	if (unlikely(dev_name == NULL)) {
		bpf_printk("error: bind mount without source\n");
		ret = -EFAULT;
		goto out;
	}
	if (unlikely(bpf_probe_read_kernel_str(&dev_name_safe, PATH_LEN,
					       dev_name) < 0)) {
		bpf_printk("error: could not read the mount dev_name\n");
		ret = -EFAULT;
		goto out;
	}
	struct paths_callback_ctx cb = { .found = false,
					 .path = dev_name_safe };

	/*
	 * NOTE(vadorovsky): Yeah, we need to check the policy yet another
	 * time. That's because BPF verifier complains when the map argument
	 * in BPF helpers is not a direct pointer to the global variable.
	 * Creating a new (struct bpf_map *) and assigning a map to it does not
	 * work - it still annoys the verifier.
	 * What's more, any attempt to move the code above to a separate
	 * function annoyed the verifier too.
	 * Therefore I was pretty much forced to either:
	 * * keep one switch statement, copy&paste a huge portion of code
	 *   between POLICY_LEVEL_RESTRICTED and POLICY_LEVEL_BASELINE arms -
	 *   that would give the best performance, but really bad readability
	 *   and maintability of code
	 * * do what I did - use two switch statements, one for initial policy
	 *   pick, then the second one after executing a common code shared
	 *   between restricted and baseline policy; not the most optimal, but
	 *   hurts my eyes less
	 * If anyone can show or contribute the better solution, I owe them a
	 * beer!
	 */
	switch (policy_level) {
	case POLICY_LEVEL_RESTRICTED:
		bpf_for_each_map_elem(&ap_mnt_restr, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("mount: restricted: allow\n");
			goto out;
		}
		break;
	case POLICY_LEVEL_BASELINE:
		bpf_for_each_map_elem(&ap_mnt_base, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("mount: baseline: allow\n");
			goto out;
		}
		break;
	defaut:
		/* unreachable */
		goto out;
	}

	bpf_printk("mount: deny\n");
	ret = -EPERM;

out:
	if (ret_prev != 0)
		return ret_prev;
	return ret;
}

/*
 * setuid_audit - LSM program triggered when user UID is changed.
 * The goal is to deny changing user ID from regular account to root user account.
 * @cred *new: data structure with new user context
 * @cred *old: data structure with old user context
 * @flags: additional flags
 * @ret_prev: return code of a previous BPF program using the sb_mount hook
 *
 * Return: 0 if changing UID is allowed. -EPERM if root account not allowed. -EFAULT if there was
 * a problem with reading the kernel strings into buffers or any important
 * buffer is NULL.
 */
SEC("lsm/task_fix_setuid")
int BPF_PROG(setuid_audit, struct cred *new, const struct cred *old, int flags, int ret_prev)
{
	int ret = 0;
	char comm[TASK_COMM_LEN];

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	enum container_policy_level policy_level = get_policy_level(pid);

	if (bpf_get_current_comm(&comm, sizeof(comm)) < 0)
		return -EFAULT;

	bpf_printk("setuid: process command: %s\n", comm);

	uid_t uid_old = BPF_CORE_READ(old, uid).val;
	bpf_printk("setuid: user current UID: %d\n", uid_old);

	uid_t uid_new = BPF_CORE_READ(new, uid).val;
	bpf_printk("setuid: user requested UID: %d\n", uid_new);

	switch (policy_level) {
	case POLICY_LEVEL_LOOKUP_ERR:
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_NOT_FOUND:
		goto out;
	case POLICY_LEVEL_RESTRICTED:
		bpf_printk("setuid: policy: restricted\n");
		break;
	case POLICY_LEVEL_BASELINE:
		bpf_printk("setuid: policy: baseline\n");
		break;
	case POLICY_LEVEL_PRIVILEGED:
		bpf_printk("setuid: root user allow\n");
		goto out;
	}

	// TODO mjura: add configuration option for what UID this restrion should be applied
	if ((uid_new == 0) && (uid_old >= 1000)) {
		bpf_printk("setuid: root user deny\n");
		ret = -EPERM;
	}

out:
	if (ret_prev != 0)
		return ret_prev;
	return ret;
}

SEC("lsm/file_open")
int BPF_PROG(open_audit, struct file *file, int ret_prev)
{
	int ret = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	enum container_policy_level policy_level = get_policy_level(pid);
	unsigned char d_path_buf[PATH_LEN] = {};

	switch (policy_level) {
	case POLICY_LEVEL_LOOKUP_ERR:
		/* Shouldn't happen */
		ret = -EPERM;
		goto out;
	case POLICY_LEVEL_NOT_FOUND:
		goto out;
	case POLICY_LEVEL_RESTRICTED:
		break;
	case POLICY_LEVEL_BASELINE:
		break;
	case POLICY_LEVEL_PRIVILEGED:
		bpf_printk("open: privileged: allow\n");
		goto out;
	}

	if (unlikely(bpf_d_path(&file->f_path, d_path_buf, PATH_LEN) < 0)) {
		bpf_printk("warn: could not read the path of opened "
			   "file\n");
		goto out;
	}
	/*
	 * Allow /, but ensure it's only / (not a prefix of everything)
	 */
	if (strcmp(d_path_buf, "/\0", 2) == 0) {
		bpf_printk("open: restricted: allow /\n");
		goto out;
	}
	struct paths_callback_ctx cb = {
		.found = false,
		.path = d_path_buf,
	};

	/*
	 * NOTE(vadorovsky): Yeah, we need to check the policy yet another
	 * time. That's because BPF verifier complains when the map argument
	 * in BPF helpers is not a direct pointer to the global variable.
	 * Creating a new (struct bpf_map *) and assigning a map to it does not
	 * work - it still annoys the verifier.
	 * What's more, any attempt to move the code above to a separate
	 * function annoyed the verifier too.
	 * Therefore I was pretty much forced to either:
	 * * keep one switch statement, copy&paste a portion of code
	 *   between POLICY_LEVEL_RESTRICTED and POLICY_LEVEL_BASELINE arms -
	 *   that would give the best performance, but really bad readability
	 *   and maintability of code
	 * * do what I did - use two switch statements, one for initial policy
	 *   pick, then the second one after executing a common code shared
	 *   between restricted and baseline policy; not the most optimal, but
	 *   hurts my eyes less
	 * If anyone can show or contribute the better solution, I owe them a
	 * beer!
	 */
	switch (policy_level) {
	case POLICY_LEVEL_RESTRICTED:
		bpf_for_each_map_elem(&ap_acc_restr, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("open: restricted: deny\n");
			ret = -EPERM;
			goto out;
		}
		cb.found = false;
		bpf_for_each_map_elem(&ap_acc_restr, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("open: restricted: allow\n");
			goto out;
		}
		break;
	case POLICY_LEVEL_BASELINE:
		bpf_for_each_map_elem(&dp_acc_base, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("open: baseline: deny\n");
			ret = -EPERM;
			goto out;
		}
		cb.found = false;
		bpf_for_each_map_elem(&ap_acc_base, check_paths, &cb, 0);
		if (cb.found) {
			bpf_printk("open: baseline: allow\n");
			goto out;
		}
		break;
	}
	bpf_printk("open: deny\n");
	ret = -EPERM;

out:
	if (ret_prev != 0)
		return ret_prev;
	return ret;
}

char __license[] SEC("license") = "GPL";
