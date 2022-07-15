/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "fdset.h"
#include "unit.h"

typedef struct Unit Unit;

int restrict_network_interfaces_supported(void);
int restrict_network_interfaces_install(Unit *u);

int serialize_restrict_network_interfaces(Unit *u, FILE *f, FDSet *fds);

/* Add BPF link fd created before daemon-reload or daemon-reexec.
 * FDs will be closed at the end of restrict_network_interfaces_install. */
int restrict_network_interfaces_add_initial_link_fd(Unit *u, int fd);
