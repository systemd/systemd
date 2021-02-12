/* SPDX-License-Identifier: LGPL-2.1+ */

#pragma once

#include <bpf/libbpf.h>

#include "macro.h"

bool can_link_bpf_program(struct bpf_program *prog);

struct bpf_link *bpf_link_free(struct bpf_link *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct bpf_link *, bpf_link_free);
