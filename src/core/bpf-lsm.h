/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

int lsm_bpf_supported(void);
int lsm_bpf_setup(void);
int bpf_restrict_filesystems(const Set *filesystems, const bool allow_list, const char *cgroup_path);
int cleanup_lsm_bpf(const char *cgroup_path);
