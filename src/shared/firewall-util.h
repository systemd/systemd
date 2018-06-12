/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "in-addr-util.h"

#if HAVE_LIBIPTC

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
