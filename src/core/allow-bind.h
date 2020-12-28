/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "bpf-link.h"
#include "macro.h"
#include "unit.h"

int allow_bind_supported(void);

int allow_bind_install(Unit *u);

/* Restore FD of BPF link created before daemon-reload or daemon-reexec.
 * Restored FDs will be closed at the end of install. */
int allow_bind_restore(Unit *u, int fd);
