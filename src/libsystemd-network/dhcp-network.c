/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>

#include "dhcp-internal.h"
#include "fd-util.h"
#include "socket-util.h"
#include "unaligned.h"

static int _bind_raw_socket(int ifindex, union sockaddr_union *link,
                            uint32_t xid, const uint8_t *mac_addr,
                            size_t mac_addr_len,
                            const uint8_t *bcast_addr,
                            const struct ether_addr *eth_mac,
                            uint16_t arp_type, uint8_t dhcp_hlen,
                            uint16_t port) {
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
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, dhcp_hlen, 1, 0),                  /* address length == dhcp_hlen ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                          /* ignore */

                /* We only support MAC address length to be either 0 or 6 (ETH_ALEN). Optionally
                 * compare chaddr for ETH_ALEN bytes. */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_ALEN, 0, 12),                                  /* A (the MAC address length) == ETH_ALEN ? */
                BPF_STMT(BPF_LD + BPF_IMM, unaligned_read_be32(&eth_mac->ether_addr_octet[0])),        /* A <- 4 bytes of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                       /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(DHCPPacket, dhcp.chaddr)),                 /* A <- 4 bytes of MAC from dhcp.chaddr */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                          /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                          /* ignore */
                BPF_STMT(BPF_LD + BPF_IMM, unaligned_read_be16(&eth_mac->ether_addr_octet[4])),        /* A <- remainder of client's MAC */
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
        int r;

        assert(ifindex > 0);
        assert(link);

        s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, SOL_PACKET, PACKET_AUXDATA, true);
        if (r < 0)
                return r;

        r = setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        link->ll = (struct sockaddr_ll) {
                .sll_family = AF_PACKET,
                .sll_protocol = htobe16(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_hatype = htobe16(arp_type),
                .sll_halen = mac_addr_len,
        };
        memcpy(link->ll.sll_addr, bcast_addr, mac_addr_len);

        r = bind(s, &link->sa, SOCKADDR_LL_LEN(link->ll));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

int dhcp_network_bind_raw_socket(int ifindex, union sockaddr_union *link,
                                 uint32_t xid, const uint8_t *mac_addr,
                                 size_t mac_addr_len, uint16_t arp_type,
                                 uint16_t port) {
        static const uint8_t eth_bcast[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        /* Default broadcast address for IPoIB */
        static const uint8_t ib_bcast[] = {
                0x00, 0xff, 0xff, 0xff, 0xff, 0x12, 0x40, 0x1b,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0xff, 0xff
          };
        struct ether_addr eth_mac = { { 0, 0, 0, 0, 0, 0 } };
        const uint8_t *bcast_addr = NULL;
        uint8_t dhcp_hlen = 0;

        if (arp_type == ARPHRD_ETHER) {
                assert_return(mac_addr_len == ETH_ALEN, -EINVAL);
                memcpy(&eth_mac, mac_addr, ETH_ALEN);
                bcast_addr = eth_bcast;
                dhcp_hlen = ETH_ALEN;
        } else if (arp_type == ARPHRD_INFINIBAND) {
                assert_return(mac_addr_len == INFINIBAND_ALEN, -EINVAL);
                bcast_addr = ib_bcast;
        } else
                return -EINVAL;

        return _bind_raw_socket(ifindex, link, xid, mac_addr, mac_addr_len,
                                bcast_addr, &eth_mac, arp_type, dhcp_hlen, port);
}

int dhcp_network_bind_udp_socket(int ifindex, be32_t address, uint16_t port) {
        union sockaddr_union src = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(port),
                .in.sin_addr.s_addr = address,
        };
        _cleanup_close_ int s = -1;
        int r;

        s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (s < 0)
                return -errno;

        r = setsockopt_int(s, IPPROTO_IP, IP_TOS, IPTOS_CLASS_CS6);
        if (r < 0)
                return r;

        r = setsockopt_int(s, SOL_SOCKET, SO_REUSEADDR, true);
        if (r < 0)
                return r;

        if (ifindex > 0) {
                r = socket_bind_to_ifindex(s, ifindex);
                if (r < 0)
                        return r;
        }

        if (address == INADDR_ANY) {
                r = setsockopt_int(s, IPPROTO_IP, IP_PKTINFO, true);
                if (r < 0)
                        return r;

                r = setsockopt_int(s, SOL_SOCKET, SO_BROADCAST, true);
                if (r < 0)
                        return r;

        } else {
                r = setsockopt_int(s, IPPROTO_IP, IP_FREEBIND, true);
                if (r < 0)
                        return r;
        }

        r = bind(s, &src.sa, sizeof(src.in));
        if (r < 0)
                return -errno;

        return TAKE_FD(s);
}

int dhcp_network_send_raw_socket(int s, const union sockaddr_union *link,
                                 const void *packet, size_t len) {
        int r;

        assert(link);
        assert(packet);
        assert(len);

        r = sendto(s, packet, len, 0, &link->sa, SOCKADDR_LL_LEN(link->ll));
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
