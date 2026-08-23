/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int bpf_bind_network_interface_supported(void);
int bpf_bind_network_interface_install(Unit *u);

int bpf_bind_network_interface_serialize(Unit *u, FILE *f, FDSet *fds);
