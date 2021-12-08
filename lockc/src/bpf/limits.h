/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/*
 * Max configurable PID limit (for x86_64, for the other architectures it's less
 * or equal).
 */
#define PID_MAX_LIMIT 4194304

/* Our arbitrary path length limit. */
#define PATH_LEN 64
#define PATH_MAX_LIMIT 128
#define PATH_MAX_DEPTH 16

/* Max length of task name (comm). */
#define TASK_COMM_LEN 16
