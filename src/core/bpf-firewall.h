/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

int bpf_firewall_read_accounting(int map_fd, uint64_t *ret_bytes, uint64_t *ret_packets);
int bpf_firewall_reset_accounting(int map_fd);
