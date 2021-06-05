/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "cgroup-util.h"

int chown_cgroup(pid_t pid, CGroupUnified unified_requested, uid_t uid_shift);
int sync_cgroup(pid_t pid, CGroupUnified unified_requested, uid_t uid_shift);
int create_subcgroup(pid_t pid, bool keep_unit, CGroupUnified unified_requested);

int mount_cgroups(const char *dest, CGroupUnified unified_requested, bool userns, uid_t uid_shift, uid_t uid_range, const char *selinux_apifs_context, bool use_cgns);
int mount_systemd_cgroup_writable(const char *dest, CGroupUnified unified_requested);
