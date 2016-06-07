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
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "fd-util.h"
#include "icmp6-util.h"
#include "socket-util.h"

#define IN6ADDR_ALL_ROUTERS_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define IN6ADDR_ALL_NODES_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }

int icmp6_bind_router_solicitation(int index) {
        struct icmp6_filter filter = { };
        struct ipv6_mreq mreq = {
                .ipv6mr_multiaddr = IN6ADDR_ALL_NODES_MULTICAST_INIT,
                .ipv6mr_interface = index,
        };
        _cleanup_close_ int s = -1;
        char ifname[IF_NAMESIZE] = "";
        static const int zero = 0, one = 1, hops = 255;
        int r;

        s = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ICMPV6);
        if (s < 0)
                return -errno;

        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
        r = setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
        if (r < 0)
                return -errno;

        /* RFC 3315, section 6.7, bullet point 2 may indicate that an
           IPV6_PKTINFO socket option also applies for ICMPv6 multicast.
           Empirical experiments indicates otherwise and therefore an
           IPV6_MULTICAST_IF socket option is used here instead */
        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, sizeof(zero));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
        if (r < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
        if (r < 0)
                return -errno;

        r = setsockopt(s, SOL_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
        if (r < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0)
                return -errno;

        if (if_indextoname(index, ifname) == 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;
        return r;
}

int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr) {
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
                .rs_opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR,
                .rs_opt.nd_opt_len = 1,
        };
        struct iovec iov = {
                .iov_base = &rs,
                .iov_len = sizeof(rs),
        };
        struct msghdr msg = {
                .msg_name = &dst,
                .msg_namelen = sizeof(dst),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        int r;

        assert(s >= 0);
        assert(ether_addr);

        rs.rs_opt_mac = *ether_addr;

        r = sendmsg(s, &msg, 0);
        if (r < 0)
                return -errno;

        return 0;
}
