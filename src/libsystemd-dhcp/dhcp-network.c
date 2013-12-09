/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.

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
#include <net/ethernet.h>
#include <stdio.h>
#include <unistd.h>

#include "socket-util.h"

#include "dhcp-internal.h"

int dhcp_network_bind_raw_socket(int index, union sockaddr_union *link)
 {
        int s;

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                   htons(ETH_P_IP));
        if (s < 0)
                return -errno;

        link->ll.sll_family = AF_PACKET;
        link->ll.sll_protocol = htons(ETH_P_IP);
        link->ll.sll_ifindex =  index;
        link->ll.sll_halen = ETH_ALEN;
        memset(link->ll.sll_addr, 0xff, ETH_ALEN);

        if (bind(s, &link->sa, sizeof(link->ll)) < 0) {
                close(s);
                return -errno;
        }

        return s;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len)
{
        int err = 0;

        if (sendto(s, packet, len, 0, &link->sa, sizeof(link->ll)) < 0)
                err = -errno;

        return err;
}
