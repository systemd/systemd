/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <stddef.h>

#include "macro.h"
#include "serialize.h"

#if HAVE_LIBBPF
struct bpf_link;
typedef struct bpf_link BPFLink;
#else
typedef void BPFLink;
#endif

int serialize_bpf_link(FILE *f, FDSet *fds, const char *key, BPFLink *link);

BPFLink *bpf_link_free(BPFLink *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(BPFLink *, bpf_link_free);
