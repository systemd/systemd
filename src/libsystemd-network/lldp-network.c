/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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
#include "lldp-internal.h"
#include "lldp-network.h"
#include "lldp-tlv.h"
#include "socket-util.h"

int lldp_network_bind_raw_socket(int ifindex) {
        typedef struct LLDPFrame {
                struct ethhdr hdr;
                uint8_t tlvs[0];
        } LLDPFrame;

        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(LLDPFrame, hdr.h_dest)),      /* A <- 4 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0180c200, 1, 0),                    /* A != 01:80:c2:00 */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(LLDPFrame, hdr.h_dest) + 4),  /* A <- remaining 2 bytes of destination MAC */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0000, 3, 0),                        /* A != 00:00 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0003, 2, 0),                        /* A != 00:03 */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x000e, 1, 0),                        /* A != 00:0e */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(LLDPFrame, hdr.h_proto)),     /* A <- protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_LLDP, 1, 0),                /* A != ETHERTYPE_LLDP */
                BPF_STMT(BPF_RET + BPF_K, 0),                                             /* drop packet */
                BPF_STMT(BPF_RET + BPF_K, (uint32_t) -1),                                 /* accept packet */
        };

        struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = filter
        };

        _cleanup_close_ int s = -1;

        union sockaddr_union saddrll = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_ifindex = ifindex,
        };

        int r;

        assert(ifindex > 0);

        s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (s < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = bind(s, &saddrll.sa, sizeof(saddrll.ll));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;

        return r;
}
