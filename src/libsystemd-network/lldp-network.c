/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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
#include <linux/if_ether.h>

#include "fd-util.h"
#include "lldp-network.h"
#include "socket-util.h"

int lldp_network_bind_raw_socket(int ifindex) {

        static const struct sock_filter filter[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ethhdr, h_dest)),      /* A <- 4 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0180c200, 1, 0),                    /* A != 01:80:c2:00 */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ethhdr, h_dest) + 4),  /* A <- remaining 2 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0000, 3, 0),                        /* A != 00:00 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0003, 2, 0),                        /* A != 00:03 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x000e, 1, 0),                        /* A != 00:0e */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ethhdr, h_proto)),     /* A <- protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_LLDP, 1, 0),                /* A != ETHERTYPE_LLDP */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_RET + BPF_K, (uint32_t) -1),                                 /* accept packet */
        };

        static const struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = (struct sock_filter*) filter,
        };

        union sockaddr_union saddrll = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_ifindex = ifindex,
        };

        _cleanup_close_ int fd = -1;
        int r;

        assert(ifindex > 0);

        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0)
                return -errno;

        r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = bind(fd, &saddrll.sa, sizeof(saddrll.ll));
        if (r < 0)
                return -errno;

        r = fd;
        fd = -1;

        return r;
}
