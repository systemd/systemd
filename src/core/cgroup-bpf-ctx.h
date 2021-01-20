/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "linux/bpf.h"
#include "list.h"

typedef struct CGroupContext CGroupContext;
typedef struct CGroupBPFFsProgram CGroupBPFFsProgram;

struct CGroupBPFFsProgram {
        LIST_FIELDS(struct CGroupBPFFsProgram, prog);
        enum bpf_attach_type attach_type;
        char *bpffs_path;
};

int bpffs_program_from_string(const char *str, enum bpf_attach_type *ret_attach_type, char **ret_bpffs_path);
int bpffs_program_to_string(enum bpf_attach_type attach_type, const char *bpffs_path, char **ret_str);

int cgroup_add_bpffs_program(CGroupContext *c, enum bpf_attach_type attach_type, const char *bpffs_path);
bool cgroup_contains_bpffs_program(
                CGroupContext *c,
                enum bpf_attach_type attach_type,
                const char *bpffs_path);
void cgroup_context_free_bpffs_program(CGroupContext *c, CGroupBPFFsProgram *p);
