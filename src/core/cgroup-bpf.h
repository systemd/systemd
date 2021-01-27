/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "set.h"

typedef struct Unit Unit;

/* Attach cgroup-bpf to a unit cgroup.
 *
 * Expect BPFProgramV2 as value type.
 * Return -EOPNOTSUPP if libbpf lib was not found at systemd compile time.
 * Return 0 if all progs were attached successfully or the error of the first
 * attach failure.
 */
int cgroup_bpf_attach_programs(Unit *u, const Set *progs, uint32_t attach_flags);

/* Detach cgroup-bpf programs attached to unit cgroup.
 *
 * Expect BPFProgramV2 as value type.
 * Try to detach all programs irregardless of detach failures.
 * Return -EOPNOTSUPP if libbpf lib was not found in systemd compile time.
 * Return 0 if all progs are detached successfully or error of the first detach
 * failure.
 */
int cgroup_bpf_detach_programs(Unit *u, const Set *progs);
