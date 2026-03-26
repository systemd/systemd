/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bpf-dlopen.h"                         /* IWYU pragma: keep */

/* libbpf is used via dlopen(), so rename symbols */
#define bpf_object__open_skeleton sym_bpf_object__open_skeleton
#define bpf_object__load_skeleton sym_bpf_object__load_skeleton
#define bpf_object__destroy_skeleton sym_bpf_object__destroy_skeleton
#define bpf_object__attach_skeleton sym_bpf_object__attach_skeleton
#define bpf_object__detach_skeleton sym_bpf_object__detach_skeleton

#include "bpf/trusted-exec/trusted-exec.skel.h" /* IWYU pragma: export */

static inline struct trusted_exec_bpf *trusted_exec_bpf_free(struct trusted_exec_bpf *obj) {
        trusted_exec_bpf__destroy(obj);
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct trusted_exec_bpf *, trusted_exec_bpf_free);
