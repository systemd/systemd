/***
  This file is part of systemd.

  Copyright (C) 2014 Axis Communications AB. All rights reserved.
  Copyright (C) 2015 Tom Gundersen

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
#include <arpa/inet.h>
#include <poll.h>

#include "util.h"
#include "arp-util.h"

#define SEND_TIMEOUT_USEC (200 * USEC_PER_MSEC)

int arp_network_bind_raw_socket(int ifindex, be32_t address, const struct ether_addr *eth_mac) {
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
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_hln)), /* A <- hardware address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct ether_addr), 1, 0),          /* length == sizeof(ether_addr)? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_pln)), /* A <- protocol address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, sizeof(struct in_addr), 1, 0),             /* length == sizeof(in_addr) ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, ea_hdr.ar_op)),  /* A <- operation */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 2, 0),                      /* protocol == request ? */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),                        /* protocol == reply ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
                /* Sender Hardware Address must be different from our own */
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(*((unsigned int *) eth_mac))),                      /* A <- 4 bytes of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                       /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_sha)),               /* A <- 4 bytes of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 6),                                          /* A == 0 ? */
                BPF_STMT(BPF_LD + BPF_IMM, htobe16(*((unsigned short *) (((char *) eth_mac) + 4)))),   /* A <- remainder of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                       /* X <- A */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_arp, arp_sha) + 4),           /* A <- remainder of SHA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                          /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                          /* ignore */
                /* Sender Protocol Address or Target Protocol Address must be equal to the one we care about*/
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(address)),                                  /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_spa)),       /* A <- SPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                  /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(address)),                                  /* A <- clients IP */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                               /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct ether_arp, arp_tpa)),       /* A <- TPA */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                        /* X xor A */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 1),                                  /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                              /* return all */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                  /* ignore */
        };
        struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = (struct sock_filter*) filter
        };
        union sockaddr_union addr = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htons(ETH_P_ARP),
                .ll.sll_ifindex = ifindex,
                .ll.sll_halen = ETH_ALEN,
                .ll.sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        _cleanup_close_ int s = -1;
        int r;

        assert(ifindex > 0);

        s = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = bind(s, &addr.sa, sizeof(addr.ll));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;

        return r;
}

static int sendto_loop(int fd, int ifindex, void *message, size_t length) {
        union sockaddr_union addr = {
                .ll.sll_family = AF_PACKET,
                .ll.sll_protocol = htons(ETH_P_ARP),
                .ll.sll_ifindex = ifindex,
                .ll.sll_halen = ETH_ALEN,
                .ll.sll_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };
        int r;

        assert(fd >= 0);
        assert(ifindex > 0);
        assert(message);

        for (;;) {
                if (sendto(fd, message, length, 0, &addr.sa, sizeof(addr.ll)) >= 0)
                        return 0;

                if (errno == EINTR)
                        continue;

                if (errno != EAGAIN)
                        return -errno;

                r = fd_wait_for_event(fd, POLLOUT, SEND_TIMEOUT_USEC);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ETIMEDOUT;
        }
}

static int arp_send_packet(int fd, int ifindex, be32_t pa, const struct ether_addr *ha, bool announce) {
        struct ether_arp arp = {
                .ea_hdr.ar_hrd = htons(ARPHRD_ETHER), /* HTYPE */
                .ea_hdr.ar_pro = htons(ETHERTYPE_IP), /* PTYPE */
                .ea_hdr.ar_hln = ETH_ALEN, /* HLEN */
                .ea_hdr.ar_pln = sizeof(struct in_addr), /* PLEN */
                .ea_hdr.ar_op = htons(ARPOP_REQUEST), /* REQUEST */
        };
        int r;

        assert(fd >= 0);
        assert(pa != 0);
        assert(ha);

        memcpy(&arp.arp_sha, ha, ETH_ALEN);
        memcpy(&arp.arp_tpa, &pa, sizeof(pa));

        if (announce)
                memcpy(&arp.arp_spa, &pa, sizeof(pa));

        r = sendto_loop(fd, ifindex, &arp, sizeof(struct ether_arp));
        if (r < 0)
                return r;

        return 0;
}

int arp_send_probe(int fd, int ifindex, be32_t pa, const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, false);
}

int arp_send_announcement(int fd, int ifindex, be32_t pa, const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, true);
}
