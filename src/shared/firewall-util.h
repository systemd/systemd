/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "in-addr-util.h"

#ifdef HAVE_LIBIPTC

int fw_add_masquerade(
                bool add,
                int af,
                int protocol,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const char *out_interface,
                const union in_addr_union *destination,
                unsigned destination_prefixlen);

int fw_add_local_dnat(
                bool add,
                int af,
                int protocol,
                const char *in_interface,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const union in_addr_union *destination,
                unsigned destination_prefixlen,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote);

#else

static inline int fw_add_masquerade(
                bool add,
                int af,
                int protocol,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const char *out_interface,
                const union in_addr_union *destination,
                unsigned destination_prefixlen) {
        return -EOPNOTSUPP;
}

static inline int fw_add_local_dnat(
                bool add,
                int af,
                int protocol,
                const char *in_interface,
                const union in_addr_union *source,
                unsigned source_prefixlen,
                const union in_addr_union *destination,
                unsigned destination_prefixlen,
                uint16_t local_port,
                const union in_addr_union *remote,
                uint16_t remote_port,
                const union in_addr_union *previous_remote) {
        return -EOPNOTSUPP;
}

#endif
