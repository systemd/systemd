/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

typedef struct Unit Unit;
typedef struct Manager Manager;

typedef struct restrict_fs_bpf restrict_fs_bpf;

int lsm_bpf_supported(void);
int lsm_bpf_setup(Manager *m);
int bpf_restrict_filesystems(Unit *u, const Set *filesystems, bool allow_list);
int cleanup_lsm_bpf(const Unit *u);
int bpf_map_restrict_fs_fd(Unit *u);
void lsm_bpf_destroy(struct restrict_fs_bpf *prog);
