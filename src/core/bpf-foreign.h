/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "linux/bpf.h"
#include "unit.h"

int bpf_foreign_program_from_string(const char *str, enum bpf_attach_type *ret_attach_type, char **ret_bpffs_path);
int bpf_foreign_program_to_string(enum bpf_attach_type attach_type, const char *bpffs_path, char **ret_str);

/*
 * Prepare foreign BPF program for installation:
 * - Load the program from BPF filesystem to the kernel;
 * - Store program FD identified by program ID and attach type in the unit.
 */
int bpf_foreign_prepare(Unit *u, enum bpf_attach_type attach_type, const char *bpffs_path);

/*
 * Detach foreign BPF programs from unit cgroup and unload them from the
 * kernel.
 * Attach programs prepared for installation.
 */
int bpf_foreign_install(Unit *u);

/*
 * Reset foreign BPF programs prepared for installation, programs not attached
 * to any cgroup will be unloaded from the kernel.
 */
void bpf_foreign_reset(Unit *u);

/* Detach and unload all foreign BPF programs. Free memory. */
void bpf_foreign_free(Unit *u);
