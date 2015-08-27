/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "socket-util.h"

#include "dhcp6-internal.h"
#include "dhcp6-protocol.h"

#define IN6ADDR_ALL_ROUTERS_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define IN6ADDR_ALL_NODES_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }

int dhcp_network_icmp6_bind_router_solicitation(int index) {
        struct icmp6_filter filter = { };
        struct ipv6_mreq mreq = {
                .ipv6mr_multiaddr = IN6ADDR_ALL_NODES_MULTICAST_INIT,
                .ipv6mr_interface = index,
        };
        _cleanup_close_ int s = -1;
        int r, zero = 0, hops = 255;

        s = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                   IPPROTO_ICMPV6);
        if (s < 0)
                return -errno;

        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
        r = setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                       sizeof(filter));
        if (r < 0)
                return -errno;

        /* RFC 3315, section 6.7, bullet point 2 may indicate that an
           IPV6_PKTINFO socket option also applies for ICMPv6 multicast.
           Empirical experiments indicates otherwise and therefore an
           IPV6_MULTICAST_IF socket option is used here instead */
        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index,
                       sizeof(index));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero,
                       sizeof(zero));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                       sizeof(hops));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
                       sizeof(mreq));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;
        return r;
}

int dhcp_network_icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {
        struct sockaddr_in6 dst = {
                .sin6_family = AF_INET6,
                .sin6_addr = IN6ADDR_ALL_ROUTERS_MULTICAST_INIT,
        };
        struct {
                struct nd_router_solicit rs;
                struct nd_opt_hdr rs_opt;
                struct ether_addr rs_opt_mac;
        } _packed_ rs = {
                .rs.nd_rs_type = ND_ROUTER_SOLICIT,
        };
        struct iovec iov[1] = {
                { &rs, },
        };
        struct msghdr msg = {
                .msg_name = &dst,
                .msg_namelen = sizeof(dst),
                .msg_iov = iov,
                .msg_iovlen = 1,
        };
        int r;

        if (ether_addr) {
                memcpy(&rs.rs_opt_mac, ether_addr, ETH_ALEN);
                rs.rs_opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
                rs.rs_opt.nd_opt_len = 1;
                iov[0].iov_len = sizeof(rs);
        } else
                iov[0].iov_len = sizeof(rs.rs);

        r = sendmsg(s, &msg, 0);
        if (r < 0)
                return -errno;

        return 0;
}

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *local_address) {
        struct in6_pktinfo pktinfo = {
                .ipi6_ifindex = index,
        };
        union sockaddr_union src = {
                .in6.sin6_family = AF_INET6,
                .in6.sin6_port = htobe16(DHCP6_PORT_CLIENT),
                .in6.sin6_addr = IN6ADDR_ANY_INIT,
        };
        _cleanup_close_ int s = -1;
        int r, off = 0, on = 1;

        if (local_address)
                memcpy(&src.in6.sin6_addr, local_address,
                       sizeof(src.in6.sin6_addr));

        s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                   IPPROTO_UDP);
        if (s < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, &pktinfo,
                       sizeof(pktinfo));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off, sizeof(off));
        if (r < 0)
                return -errno;

        r = bind(s, &src.sa, sizeof(src.in6));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;
        return r;
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
