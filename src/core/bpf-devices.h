/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

#include "unit.h"

struct BPFProgram;

int bpf_devices_supported(void);

int cgroup_bpf_whitelist_device(BPFProgram *p, int type, int major, int minor, const char *acc);
int cgroup_bpf_whitelist_major(BPFProgram *p, int type, int major, const char *acc);
int cgroup_bpf_whitelist_class(BPFProgram *prog, int type, const char *acc);

int cgroup_init_device_bpf(BPFProgram **ret, CGroupDevicePolicy policy, bool whitelist);
int cgroup_apply_device_bpf(Unit *u, BPFProgram *p, CGroupDevicePolicy policy, bool whitelist);
