/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int bpf_restrict_ifaces_supported(void);
int bpf_restrict_ifaces_install(Unit *u);

int bpf_restrict_ifaces_serialize(Unit *u, FILE *f, FDSet *fds);

/* Add BPF link fd created before daemon-reload or daemon-reexec.
 * FDs will be closed at the end of restrict_network_interfaces_install. */
int bpf_restrict_ifaces_add_initial_link_fd(Unit *u, int fd);
