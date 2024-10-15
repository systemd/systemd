/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <bpf/libbpf.h>
#include <stdio.h>

#include "fdset.h"
#include "macro.h"

bool bpf_can_link_program(struct bpf_program *prog);

int bpf_serialize_link(FILE *f, FDSet *fds, const char *key, struct bpf_link *link);

struct bpf_link* bpf_link_free(struct bpf_link *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct bpf_link *, bpf_link_free);

struct ring_buffer* bpf_ring_buffer_free(struct ring_buffer *rb);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct ring_buffer *, bpf_ring_buffer_free);
