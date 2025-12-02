/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int bpf_vrf_bind_supported(void);
int bpf_vrf_bind_install(Unit *u);

int bpf_vrf_bind_serialize(Unit *u, FILE *f, FDSet *fds);
