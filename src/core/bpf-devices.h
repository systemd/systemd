/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "cgroup.h"

typedef struct BPFProgram BPFProgram;

int bpf_devices_cgroup_init(BPFProgram **ret, CGroupDevicePolicy policy, bool allow_list);
int bpf_devices_apply_policy(
                BPFProgram **prog,
                CGroupDevicePolicy policy,
                bool allow_list,
                const char *cgroup_path,
                BPFProgram **prog_installed);

int bpf_devices_supported(void);
int bpf_devices_allow_list_device(BPFProgram *prog, const char *path, const char *node, const char *acc);
int bpf_devices_allow_list_major(BPFProgram *prog, const char *path, const char *name, char type, const char *acc);
int bpf_devices_allow_list_static(BPFProgram *prog, const char *path);
