/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

bool bpf_socket_ratelimit_supported(void);
int bpf_socket_ratelimit_setup(Manager *m);
int bpf_socket_ratelimit_install(Unit *u, uint64_t interval, uint64_t burst);
int bpf_socket_ratelimit_cleanup(Unit *u);
int bpf_socket_ratelimit_serialize(Manager *m, FILE *f, FDSet *fds);

struct socket_ratelimit_bpf;
void bpf_socket_ratelimit_destroy(struct socket_ratelimit_bpf *obj);
