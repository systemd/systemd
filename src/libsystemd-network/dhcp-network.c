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
#include <net/if_arp.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/filter.h>

#include "socket-util.h"

#include "dhcp-internal.h"

int dhcp_network_bind_raw_socket(int index, union sockaddr_union *link,
                                 uint32_t xid, struct ether_addr mac_addr) {
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                 /* A <- packet length */
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(DHCPPacket), 1, 0),         /* packet >= DHCPPacket ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, ip.protocol)), /* A <- IP protocol */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                /* IP protocol == UDP ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, ip.frag_off)), /* A <- Flags + Fragment offset */
            BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x1fff),                           /* A <- A & 0x1fff */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                          /* A == 0 ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, udp.dest)),    /* A <- UDP destination port */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_PORT_CLIENT, 1, 0),           /* UDP destination port == DHCP client port ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.op)),     /* A <- DHCP op */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTREPLY, 1, 0),                  /* op == BOOTREPLY ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.htype)),  /* A <- DHCP header type */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),               /* header type == ARPHRD_ETHER ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.hlen)),   /* A <- mac address length */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHER_ADDR_LEN, 1, 0),             /* address length == ETHER_ADDR_LEN ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.xid)),    /* A <- client identifier */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, xid, 1, 0),                        /* client identifier == xid ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_IMM, htobe32(*((unsigned int *) &mac_addr))),                    /* A <- 4 bytes of client's MAC */
            BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                       /* X <- A */
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.chaddr)),                 /* A <- 4 bytes of MAC from dhcp.chaddr */
            BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                /* A xor X */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                          /* A == 0 ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_IMM, htobe16(*((unsigned short *) (((char *) &mac_addr) + 4)))), /* A <- remainder of client's MAC */
            BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                       /* X <- A */
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, dhcp.chaddr) + 4),             /* A <- remainder of MAC from dhcp.chaddr */
            BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                /* A xor X */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                          /* A == 0 ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                                          /* ignore */
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.magic)),  /* A <- DHCP magic cookie */
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_MAGIC_COOKIE, 1, 0),          /* cookie == DHCP magic cookie ? */
            BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
            BPF_STMT(BPF_RET + BPF_K, 65535),                                      /* return all */
        };
        struct sock_fprog fprog = {
            .len = ELEMENTSOF(filter),
            .filter = filter
        };
        _cleanup_close_ int s = -1;
        int r, on = 1;

        assert(index > 0);
        assert(link);

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt (s, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        link->ll.sll_family = AF_PACKET;
        link->ll.sll_protocol = htons(ETH_P_IP);
        link->ll.sll_ifindex =  index;
        link->ll.sll_halen = ETH_ALEN;
        memset(link->ll.sll_addr, 0xff, ETH_ALEN);

        r = bind(s, &link->sa, sizeof(link->ll));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;

        return r;
}

int dhcp_network_bind_udp_socket(be32_t address, uint16_t port) {
        union sockaddr_union src = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = address,
        };
        _cleanup_close_ int s = -1;
        int r, tos = IPTOS_CLASS_CS6;

        s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0)
                return -errno;

        if (address == INADDR_ANY) {
                int on = 1;

                r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
                if (r < 0)
                        return -errno;

                r = setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
                if (r < 0)
                        return -errno;

                r = setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
                if (r < 0)
                        return -errno;
        }

        r = bind(s, &src.sa, sizeof(src.in));
        if (r < 0)
                return -errno;

        r = s;
        s = -1;

        return r;
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len) {
        int r;

        assert(link);
        assert(packet);
        assert(len);

        r = sendto(s, packet, len, 0, &link->sa, sizeof(link->ll));
        if (r < 0)
                return -errno;

        return 0;
}

int dhcp_network_send_udp_socket(int s, be32_t address, uint16_t port,
                                 const void *packet, size_t len) {
        union sockaddr_union dest = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = address,
        };
        int r;

        assert(s >= 0);
        assert(packet);
        assert(len);

        r = sendto(s, packet, len, 0, &dest.sa, sizeof(dest.in));
        if (r < 0)
                return -errno;

        return 0;
}
