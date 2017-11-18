/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.

  [Except for the stuff copy/pasted from the kernel sources, see below]
***/

#include <linux/bpf.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "list.h"
#include "macro.h"

typedef struct BPFProgram BPFProgram;

struct BPFProgram {
        int kernel_fd;
        uint32_t prog_type;

        size_t n_instructions;
        size_t allocated;
        struct bpf_insn *instructions;
};

int bpf_program_new(uint32_t prog_type, BPFProgram **ret);
BPFProgram *bpf_program_unref(BPFProgram *p);

int bpf_program_add_instructions(BPFProgram *p, const struct bpf_insn *insn, size_t count);
int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size);

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *path, uint32_t flags);
int bpf_program_cgroup_detach(int type, const char *path);

int bpf_map_new(enum bpf_map_type type, size_t key_size, size_t value_size, size_t max_entries, uint32_t flags);
int bpf_map_update_element(int fd, const void *key, void *value);
int bpf_map_lookup_element(int fd, const void *key, void *value);

DEFINE_TRIVIAL_CLEANUP_FUNC(BPFProgram*, bpf_program_unref);
