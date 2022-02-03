/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_packet.h>

#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "socket-util.h"

int dhcp6_network_bind_udp_socket(int ifindex, struct in6_addr *local_address) {
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
                .in6.sin6_scope_id = ifindex,
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(ifindex > 0);
        assert(local_address);

        src.in6.sin6_addr = *local_address;

        s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_V6ONLY, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, false);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return r;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

int dhcp6_network_send_udp_socket(int s, struct in6_addr *server_address,
                                  const void *packet, size_t len) {
        union sockaddr_union dest = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(DHCP6_PORT_SERVER),
        };
        int r;

        assert(server_address);

        memcpy(&dest.in6.sin6_addr, server_address, sizeof(dest.in6.sin6_addr));

        r = sendto(s, packet, len, 0, &dest.sa, sizeof(dest.in6));
        if (r < 0)
                return -errno;

        return 0;
}
