/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stddef.h>

#include "macro.h"
#include "serialize.h"

#if HAVE_LIBBPF
struct bpf_link;
typedef struct bpf_link BpfLink;
struct bpf_program;
typedef struct bpf_program BpfProgram;
#else
typedef void BpfLink;
typedef void BpfProgram;
#endif

bool can_link_bpf_program(BpfProgram *prog);

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BpfLink *link);

BpfLink *bpf_link_free(BpfLink *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(BpfLink *, bpf_link_free);
