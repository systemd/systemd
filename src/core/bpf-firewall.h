/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>

#include "unit.h"

enum {
        BPF_FIREWALL_UNSUPPORTED          = 0,
        BPF_FIREWALL_SUPPORTED            = 1,
        BPF_FIREWALL_SUPPORTED_WITH_MULTI = 2,
};

int bpf_firewall_supported(void);

int bpf_firewall_compile(Unit *u);
int bpf_firewall_install(Unit *u);
int bpf_firewall_load_custom(Unit *u);

int bpf_firewall_read_accounting(int map_fd, uint64_t *ret_bytes, uint64_t *ret_packets);
int bpf_firewall_reset_accounting(int map_fd);

void emit_bpf_firewall_warning(Unit *u);
