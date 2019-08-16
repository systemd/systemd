/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/bpf.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "list.h"
#include "macro.h"

typedef struct BPFProgram BPFProgram;

struct BPFProgram {
        unsigned n_ref;

        int kernel_fd;
        uint32_t prog_type;

        size_t n_instructions;
        size_t allocated;
        struct bpf_insn *instructions;

        char *attached_path;
        int attached_type;
        uint32_t attached_flags;
};

int bpf_program_new(uint32_t prog_type, BPFProgram **ret);
BPFProgram *bpf_program_unref(BPFProgram *p);
BPFProgram *bpf_program_ref(BPFProgram *p);

int bpf_program_add_instructions(BPFProgram *p, const struct bpf_insn *insn, size_t count);
int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size);
int bpf_program_load_from_bpf_fs(BPFProgram *p, const char *path);

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *path, uint32_t flags);
int bpf_program_cgroup_detach(BPFProgram *p);

int bpf_map_new(enum bpf_map_type type, size_t key_size, size_t value_size, size_t max_entries, uint32_t flags);
int bpf_map_update_element(int fd, const void *key, void *value);
int bpf_map_lookup_element(int fd, const void *key, void *value);

DEFINE_TRIVIAL_CLEANUP_FUNC(BPFProgram*, bpf_program_unref);
