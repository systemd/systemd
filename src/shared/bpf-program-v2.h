/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <bpf/bpf.h>

#include "macro.h"

typedef struct BPFProgramV2 BPFProgramV2;
struct BPFProgramV2 {
        int fd;
        enum bpf_attach_type attach_type;
};

int bpf_program_v2_new(int fd, enum bpf_attach_type attach_type, BPFProgramV2 **ret);
BPFProgramV2 *bpf_program_v2_free(BPFProgramV2 *p);

int bpf_program_v2_cgroup_attach(const BPFProgramV2 *p, const char *cgroup_path, uint32_t attach_flags);
int bpf_program_v2_cgroup_detach(const BPFProgramV2 *p, const char *cgroup_path);

DEFINE_TRIVIAL_CLEANUP_FUNC(BPFProgramV2 *, bpf_program_v2_free);
