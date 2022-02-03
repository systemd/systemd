/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "unit.h"

static inline int bpf_foreign_supported(void) {
        return cg_all_unified();
}

/*
 * Attach cgroup-bpf programs foreign to systemd, i.e. loaded to the kernel by an entity
 * external to systemd.
 */
int bpf_foreign_install(Unit *u);
