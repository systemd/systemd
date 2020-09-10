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

int cgroup_add_bpffs_program(CGroupContext *c, enum bpf_attach_type attach_type, const char *bpffs_path);
bool cgroup_contains_bpffs_program(
                CGroupContext *c,
                enum bpf_attach_type attach_type,
                const char *bpffs_path);
void cgroup_context_free_bpffs_program(CGroupContext *c, CGroupBPFFsProgram *p);
