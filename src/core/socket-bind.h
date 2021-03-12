/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "bpf-link.h"
#include "macro.h"

typedef struct Unit Unit;

int socket_bind_supported(void);

int socket_bind_install(Unit *u);

/* Restore FD of BPF link created before daemon-reload or daemon-reexec.
 * Restored FDs will be closed at the end of install. */
int socket_bind_restore(Unit *u, int fd);
