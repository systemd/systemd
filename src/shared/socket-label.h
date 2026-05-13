/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef enum SocketAddressBindIPv6Only {
        SOCKET_ADDRESS_DEFAULT,
        SOCKET_ADDRESS_BOTH,
        SOCKET_ADDRESS_IPV6_ONLY,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_MAX,
        _SOCKET_ADDRESS_BIND_IPV6_ONLY_INVALID = -EINVAL,
} SocketAddressBindIPv6Only;

DECLARE_STRING_TABLE_LOOKUP(socket_address_bind_ipv6_only, SocketAddressBindIPv6Only);
DECLARE_STRING_TABLE_LOOKUP_FROM_STRING(socket_address_bind_ipv6_only_or_bool, SocketAddressBindIPv6Only);

int socket_address_listen(
                const SocketAddress *a,
                int flags,
                int backlog,
                SocketAddressBindIPv6Only only,
                const char *bind_to_device,
                bool reuse_port,
                bool free_bind,
                bool transparent,
                mode_t directory_mode,
                mode_t socket_mode,
                const char *selinux_label,
                const char *smack_label);
