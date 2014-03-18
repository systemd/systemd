/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.

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

#include "util.h"
#include "ipv4ll-internal.h"

int arp_network_send_raw_socket(int fd, const union sockaddr_union *link,
                                        const struct ether_arp *arp) {
        assert(arp);
        assert(link);
        assert(fd >= 0);

        if (sendto(fd, arp, sizeof(struct ether_arp), 0, &link->sa, sizeof(link->ll)) < 0)
                return -errno;

        return 0;
}

int arp_network_bind_raw_socket(int index, union sockaddr_union *link) {
        int s;

        assert(index > 0);
        assert(link);

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ARP));
        if (s < 0)
                return -errno;

        link->ll.sll_family = AF_PACKET;
        link->ll.sll_ifindex = index;
        link->ll.sll_protocol = htons(ETH_P_ARP);
        link->ll.sll_halen = ETH_ALEN;

        if (bind(s, &link->sa, sizeof(link->ll)) < 0) {
                safe_close(s);
                return -errno;
        }

        return s;
}
