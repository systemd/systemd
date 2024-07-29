/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>

#include "fdset.h"
#include "list.h"
#include "macro.h"

typedef struct BPFProgram BPFProgram;

/* This encapsulates three different concepts: the loaded BPF program, the BPF code, and the attachment to a
 * cgroup. Typically our BPF programs go through all three stages: we build the code, we load it, and finally
 * we attach it, but it might happen that we operate with programs that aren't loaded or aren't attached, or
 * where we don't have the code. */
struct BPFProgram {
        /* The loaded BPF program, if loaded */
        int kernel_fd;
        uint32_t prog_type;
        char *prog_name;

        /* The code of it BPF program, if known */
        size_t n_instructions;
        struct bpf_insn *instructions;

        /* The cgroup path the program is attached to, if it is attached. If non-NULL bpf_program_unref()
         * will detach on destruction. */
        char *attached_path;
        int attached_type;
        uint32_t attached_flags;
};

int bpf_program_new(uint32_t prog_type, const char *prog_name, BPFProgram **ret);
int bpf_program_new_from_bpffs_path(const char *path, BPFProgram **ret);
BPFProgram *bpf_program_free(BPFProgram *p);

int bpf_program_add_instructions(BPFProgram *p, const struct bpf_insn *insn, size_t count);
int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size);
int bpf_program_load_from_bpf_fs(BPFProgram *p, const char *path);

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *path, uint32_t flags);
int bpf_program_cgroup_detach(BPFProgram *p);

int bpf_program_pin(int prog_fd, const char *bpffs_path);
int bpf_program_get_id_by_fd(int prog_fd, uint32_t *ret_id);

int bpf_program_serialize_attachment(FILE *f, FDSet *fds, const char *key, BPFProgram *p);
int bpf_program_serialize_attachment_set(FILE *f, FDSet *fds, const char *key, Set *set);
int bpf_program_deserialize_attachment(const char *v, FDSet *fds, BPFProgram **bpfp);
int bpf_program_deserialize_attachment_set(const char *v, FDSet *fds, Set **bpfsetp);

extern const struct hash_ops bpf_program_hash_ops;

int bpf_map_new(const char *name, enum bpf_map_type type, size_t key_size, size_t value_size,
                size_t max_entries, uint32_t flags);
int bpf_map_update_element(int fd, const void *key, void *value);
int bpf_map_lookup_element(int fd, const void *key, void *value);

int bpf_cgroup_attach_type_from_string(const char *str) _pure_;
const char* bpf_cgroup_attach_type_to_string(int attach_type) _const_;

DEFINE_TRIVIAL_CLEANUP_FUNC(BPFProgram*, bpf_program_free);
