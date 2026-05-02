/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <netinet/ip.h>

#include "dhcp-network.h"
#include "dhcp-protocol.h"
#include "fd-util.h"
#include "iovec-wrapper.h"
#include "socket-util.h"

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port, int ip_service_type) {
        union sockaddr_union src = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = address,
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        if (ip_service_type >= 0)
                r = setsockopt_int(s, IPPROTO_IP, IP_TOS, ip_service_type);
        else
                r = setsockopt_int(s, IPPROTO_IP, IP_TOS, IPTOS_CLASS_CS6);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return r;

        if (ifindex > 0) {
                r = socket_bind_to_ifindex(s, ifindex);
                if (r < 0)
                        return r;
        }

        if (port == DHCP_PORT_SERVER) {
                r = setsockopt_int(s, SOL_SOCKET, SO_BROADCAST, true);
                if (r < 0)
                        return r;
                if (address == INADDR_ANY) {
                        /* IP_PKTINFO filter should not be applied when packets are
                           allowed to enter/leave through the interface other than
                           DHCP server sits on(BindToInterface option). */
                        r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, true);
                        if (r < 0)
                                return r;
                }
        } else {
                r = setsockopt_int(s, IPPROTO_IP, IP_FREEBIND, true);
                if (r < 0)
                        return r;
        }

        if (bind(s, &src.sa, sizeof(src.in)) < 0)
                return -errno;

        return TAKE_FD(s);
}

int dhcp_network_send_raw_socket(
                int fd,
                const union sockaddr_union *link,
                const struct iovec_wrapper *iovw) {

        /* Do not add assert(fd >= 0) here, as this is also called from fuzz-dhcp-server, and in that case
         * fd is negative and this function should fail with negative errno. */

        assert(link);
        assert(!iovw_isempty(iovw));

        struct msghdr mh = {
                .msg_name = (struct sockaddr*) &link->sa,
                .msg_namelen = sockaddr_ll_len(&link->ll),
                .msg_iov = iovw->iovec,
                .msg_iovlen = iovw->count,
        };

        if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}
