/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>

#include "dhcp-network.h"
#include "dhcp-protocol.h"
#include "fd-util.h"
#include "unaligned.h"

static int _bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t xid,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *bcast_addr,
                uint16_t arp_type,
                uint16_t port,
                bool so_priority_set,
                int so_priority) {

        assert(ifindex > 0);
        assert(link);
        assert(hw_addr);
        assert(bcast_addr);
        assert(IN_SET(arp_type, ARPHRD_ETHER, ARPHRD_INFINIBAND));

        switch (arp_type) {
        case ARPHRD_ETHER:
                assert(hw_addr->length == ETH_ALEN);
                assert(bcast_addr->length == ETH_ALEN);
                break;
        case ARPHRD_INFINIBAND:
                assert(hw_addr->length == 0);
                assert(bcast_addr->length == INFINIBAND_ALEN);
                break;
        default:
                assert_not_reached();
        }

        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                 /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(DHCPPacket), 1, 0),         /* packet >= DHCPPacket ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, ip.protocol)), /* A <- IP protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                /* IP protocol == UDP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, ip.frag_off)), /* A <- Flags */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x20),                             /* A <- A & 0x20 (More Fragments bit) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                          /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, ip.frag_off)), /* A <- Flags + Fragment offset */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x1fff),                           /* A <- A & 0x1fff (Fragment offset) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                          /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, udp.dest)),    /* A <- UDP destination port */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 1, 0),                       /* UDP destination port == DHCP client port ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.op)),     /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, BOOTREPLY, 1, 0),                  /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.htype)),  /* A <- DHCP header type */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arp_type, 1, 0),                   /* header type == arp_type ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.xid)),    /* A <- client identifier */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, xid, 1, 0),                        /* client identifier == xid ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(DHCPPacket, dhcp.hlen)),   /* A <- MAC address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (uint8_t) hw_addr->length, 1, 0),  /* address length == hw_addr->length ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* We only support MAC address length to be either 0 or 6 (ETH_ALEN). Optionally
                 * compare chaddr for ETH_ALEN bytes. */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_ALEN, 0, 8),                        /* A (the MAC address length) == ETH_ALEN ? */
                BPF_STMT(BPF_LDX + BPF_IMM, unaligned_read_be32(hw_addr->bytes)),           /* X <- 4 bytes of client's MAC */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.chaddr)),      /* A <- 4 bytes of MAC from dhcp.chaddr */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_X, 0, 1, 0),                               /* A == X ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* ignore */
                BPF_STMT(BPF_LDX + BPF_IMM, unaligned_read_be16(hw_addr->bytes + 4)),       /* X <- remainder of client's MAC */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(DHCPPacket, dhcp.chaddr) + 4),  /* A <- remainder of MAC from dhcp.chaddr */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_X, 0, 1, 0),                               /* A == X ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                               /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.magic)),  /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_MAGIC_COOKIE, 1, 0),          /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */
                BPF_STMT(BPF_RET + BPF_K, UINT32_MAX),                                 /* accept */
        };
        struct sock_fprog fprog = {
                .len = ELEMENTSOF(filter),
                .filter = filter
        };
        _cleanup_close_ int s = -EBADF;
        int r;

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, SOL_PACKET, PACKET_AUXDATA, true);
        if (r < 0)
                return r;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = setsockopt_int(s, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return r;

        if (so_priority_set) {
                r = setsockopt_int(s, SOL_SOCKET, SO_PRIORITY, so_priority);
                if (r < 0)
                        return r;
        }

        link->ll = (struct sockaddr_ll) {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_hatype = htobe16(arp_type),
                .sll_halen = bcast_addr->length,
        };
        /* We may overflow link->ll. link->ll_buffer ensures we have enough space. */
        memcpy(link->ll.sll_addr, bcast_addr->bytes, bcast_addr->length);

        r = bind(s, &link->sa, SOCKADDR_LL_LEN(link->ll));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t xid,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *bcast_addr,
                uint16_t arp_type,
                uint16_t port,
                bool so_priority_set,
                int so_priority) {

        static struct hw_addr_data default_eth_bcast = {
                .length = ETH_ALEN,
                .ether = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }},
        }, default_ib_bcast = {
                .length = INFINIBAND_ALEN,
                .infiniband = {
                        0x00, 0xff, 0xff, 0xff, 0xff, 0x12, 0x40, 0x1b,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0xff, 0xff, 0xff, 0xff
                },
        };

        assert(ifindex > 0);
        assert(link);
        assert(hw_addr);

        switch (arp_type) {
        case ARPHRD_ETHER:
                return _bind_raw_socket(ifindex, link, xid,
                                        hw_addr,
                                        (bcast_addr && !hw_addr_is_null(bcast_addr)) ? bcast_addr : &default_eth_bcast,
                                        arp_type, port, so_priority_set, so_priority);

        case ARPHRD_INFINIBAND:
                return _bind_raw_socket(ifindex, link, xid,
                                        &HW_ADDR_NULL,
                                        (bcast_addr && !hw_addr_is_null(bcast_addr)) ? bcast_addr : &default_ib_bcast,
                                        arp_type, port, so_priority_set, so_priority);
        default:
                return -EINVAL;
        }
}

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
                int s,
                const union sockaddr_union *link,
                const void *packet,
                size_t len) {

        /* Do not add assert(s >= 0) here, as this is called in fuzz-dhcp-server, and in that case this
         * function should fail with negative errno. */

        assert(link);
        assert(packet);
        assert(len > 0);

        if (sendto(s, packet, len, 0, &link->sa, SOCKADDR_LL_LEN(link->ll)) < 0)
                return -errno;

        return 0;
}

int dhcp_network_send_udp_socket(
                int s,
                be32_t address,
                uint16_t port,
                const void *packet,
                size_t len) {

        union sockaddr_union dest = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = address,
        };

        assert(s >= 0);
        assert(packet);
        assert(len > 0);

        if (sendto(s, packet, len, 0, &dest.sa, sizeof(dest.in)) < 0)
                return -errno;

        return 0;
}
