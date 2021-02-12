/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include "macro.h"

#if HAVE_LIBBPF
struct bpf_link;
typedef struct bpf_link BPFLink;
#else
typedef void BPFLink;
#endif

BPFLink *bpf_link_free(BPFLink *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(BPFLink *, bpf_link_free);
