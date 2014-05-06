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

#include <linux/filter.h>

#include "util.h"
#include "ipv4ll-internal.h"

int arp_network_send_raw_socket(int fd, const union sockaddr_union *link,
                                        const struct ether_arp *arp) {
        int r;

        assert(arp);
        assert(link);
        assert(fd >= 0);

        r = sendto(fd, arp, sizeof(struct ether_arp), 0, &link->sa, sizeof(link->ll));
        if (r < 0)
                return -errno;

        return 0;
}

int arp_network_bind_raw_socket(int index, union sockaddr_union *link) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                         /* A <- packet length */
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct ether_arp), 1, 0),           /* packet >= arp packet ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hrd)), /* A <- header */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),                       /* header == ethernet ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pro)), /* A <- protocol */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 1, 0),                       /* protocol == IP ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_op)),  /* A <- operation */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 0, 1),                      /* protocol == request ? */
            BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 0, 1),                        /* protocol == reply ? */
            BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
        };
        struct sock_fprog fprog = {
            .len = ELEMENTSOF(filter),
            .filter = filter
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(index > 0);
        assert(link);

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        link->ll.sll_family = AF_PACKET;
        link->ll.sll_protocol = htons(ETH_P_ARP);
        link->ll.sll_ifindex = index;
        link->ll.sll_halen = ETH_ALEN;
        memset(link->ll.sll_addr, 0xff, ETH_ALEN);

        r = bind(s, &link->sa, sizeof(link->ll));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;

        return r;
}
