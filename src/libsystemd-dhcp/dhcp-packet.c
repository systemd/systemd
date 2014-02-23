/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation. All rights reserved.
  Copyright (C) 2014 Tom Gundersen

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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <sys/param.h>

#include "util.h"
#include "list.h"

#include "dhcp-protocol.h"
#include "dhcp-lease.h"
#include "dhcp-internal.h"
#include "sd-dhcp-client.h"

#define DHCP_CLIENT_MIN_OPTIONS_SIZE            312

int dhcp_message_init(DHCPMessage *message, uint8_t op, uint32_t xid,
                      uint8_t type, uint16_t secs, uint8_t **opt,
                      size_t *optlen) {
        int err;

        *opt = (uint8_t *)(message + 1);

        if (*optlen < 4)
                return -ENOBUFS;
        *optlen -= 4;

        message->op = op;
        message->htype = ARPHRD_ETHER;
        message->hlen = ETHER_ADDR_LEN;
        message->xid = htobe32(xid);

        /* Although 'secs' field is a SHOULD in RFC 2131, certain DHCP servers
           refuse to issue an DHCP lease if 'secs' is set to zero */
        message->secs = htobe16(secs);

        (*opt)[0] = 0x63;
        (*opt)[1] = 0x82;
        (*opt)[2] = 0x53;
        (*opt)[3] = 0x63;

        *opt += 4;

        err = dhcp_option_append(opt, optlen, DHCP_OPTION_MESSAGE_TYPE, 1,
                                 &type);
        if (err < 0)
                return err;

        return 0;
}

static uint16_t dhcp_checksum(void *buf, int len) {
        uint32_t sum;
        uint16_t *check;
        int i;
        uint8_t *odd;

        sum = 0;
        check = buf;

        for (i = 0; i < len / 2 ; i++)
                sum += check[i];

        if (len & 0x01) {
                odd = buf;
                sum += odd[len - 1];
        }

        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

void dhcp_packet_append_ip_headers(DHCPPacket *packet, uint8_t op,
                                   uint16_t len) {
        assert(op == BOOTREQUEST || op == BOOTREPLY);

        packet->ip.version = IPVERSION;
        packet->ip.ihl = DHCP_IP_SIZE / 4;
        packet->ip.tot_len = htobe16(len);

        packet->ip.protocol = IPPROTO_UDP;
        packet->ip.saddr = INADDR_ANY;
        packet->ip.daddr = INADDR_BROADCAST;

        switch (op) {
                case BOOTREQUEST:
                        packet->udp.source = htobe16(DHCP_PORT_CLIENT);
                        packet->udp.dest = htobe16(DHCP_PORT_SERVER);
                        break;
                case BOOTREPLY:
                        packet->udp.source = htobe16(DHCP_PORT_SERVER);
                        packet->udp.dest = htobe16(DHCP_PORT_CLIENT);
                        break;
        }

        packet->udp.len = htobe16(len - DHCP_IP_SIZE);

        packet->ip.check = packet->udp.len;
        packet->udp.check = dhcp_checksum(&packet->ip.ttl, len - 8);

        packet->ip.ttl = IPDEFTTL;
        packet->ip.check = 0;
        packet->ip.check = dhcp_checksum(&packet->ip, DHCP_IP_SIZE);
}

int dhcp_packet_verify_headers(DHCPPacket *packet, uint8_t op, size_t len) {
        size_t hdrlen;

        assert(op == BOOTREQUEST || op == BOOTREPLY);

        if (len < (DHCP_IP_UDP_SIZE + DHCP_MESSAGE_SIZE)) {
                log_dhcp_client(client, "ignoring packet: packet too small");
                return -EINVAL;
        }

        hdrlen = packet->ip.ihl * 4;
        if (hdrlen < 20 || hdrlen > len) {
                log_dhcp_client(client, "ignoring packet: header with wrong size");
                return -EINVAL;
        }

        if (dhcp_checksum(&packet->ip, hdrlen)) {
                log_dhcp_client(client, "ignoring packet: invalid ip checksum");
                return -EINVAL;
        }

        if (hdrlen + be16toh(packet->udp.len) > len) {
                log_dhcp_client(client, "ignoring packet: packet too small (udp.len=%u)",
                                be16toh(packet->udp.len));
                return -EINVAL;
        }

        if (packet->udp.check) {
                packet->ip.check = packet->udp.len;
                packet->ip.ttl = 0;

                if (dhcp_checksum(&packet->ip.ttl,
                                  be16toh(packet->udp.len) + 12)) {
                        log_dhcp_client(client, "ignoring packet: invalid udp checksum");
                        return -EINVAL;
                }
        }

        if (packet->dhcp.op != op) {
                log_dhcp_client(client, "ignoring packet: wrong operation");
                return -EINVAL;
        }

        switch (op) {
                case BOOTREQUEST:
                        if (be16toh(packet->udp.source) != DHCP_PORT_CLIENT ||
                            be16toh(packet->udp.dest) != DHCP_PORT_SERVER) {
                                log_dhcp_client(client, "ignoring packet: wrong ports");
                                return -EINVAL;
                        }
                        break;
                case BOOTREPLY:
                        if (be16toh(packet->udp.source) != DHCP_PORT_SERVER ||
                            be16toh(packet->udp.dest) != DHCP_PORT_CLIENT) {
                                log_dhcp_client(client, "ignoring packet: wrong ports");
                                return -EINVAL;
                        }
                        break;
        }

        return 0;
}
