/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <errno.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <string.h>

#include "dhcp-internal.h"
#include "dhcp-protocol.h"
#include "memory-util.h"

#define DHCP_CLIENT_MIN_OPTIONS_SIZE            312

int dhcp_message_init(
                DHCPMessage *message,
                uint8_t op,
                uint32_t xid,
                uint8_t type,
                uint16_t arp_type,
                uint8_t hlen,
                const uint8_t *chaddr,
                size_t optlen,
                size_t *optoffset) {

        size_t offset = 0;
        int r;

        assert(IN_SET(op, BOOTREQUEST, BOOTREPLY));
        assert(chaddr || hlen == 0);

        message->op = op;
        message->htype = arp_type;

        /* RFC2131 section 4.1.1:
           The client MUST include its hardware address in the ’chaddr’ field, if
           necessary for delivery of DHCP reply messages.

           RFC 4390 section 2.1:
           A DHCP client, when working over an IPoIB interface, MUST follow the
           following rules:
           "htype" (hardware address type) MUST be 32 [ARPPARAM].
           "hlen" (hardware address length) MUST be 0.
           "chaddr" (client hardware address) field MUST be zeroed.
         */
        message->hlen = arp_type == ARPHRD_INFINIBAND ? 0 : hlen;
        memcpy_safe(message->chaddr, chaddr, message->hlen);

        message->xid = htobe32(xid);
        message->magic = htobe32(DHCP_MAGIC_COOKIE);

        r = dhcp_option_append(message, optlen, &offset, 0,
                               SD_DHCP_OPTION_MESSAGE_TYPE, 1, &type);
        if (r < 0)
                return r;

        *optoffset = offset;

        return 0;
}

uint16_t dhcp_packet_checksum(uint8_t *buf, size_t len) {
        uint64_t *buf_64 = (uint64_t*)buf;
        uint64_t *end_64 = buf_64 + (len / sizeof(uint64_t));
        uint64_t sum = 0;

        /* See RFC1071 */

        while (buf_64 < end_64) {
                sum += *buf_64;
                if (sum < *buf_64)
                        /* wrap around in one's complement */
                        sum++;

                buf_64++;
        }

        if (len % sizeof(uint64_t)) {
                /* If the buffer is not aligned to 64-bit, we need
                   to zero-pad the last few bytes and add them in */
                uint64_t buf_tail = 0;

                memcpy(&buf_tail, buf_64, len % sizeof(uint64_t));

                sum += buf_tail;
                if (sum < buf_tail)
                        /* wrap around */
                        sum++;
        }

        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

void dhcp_packet_append_ip_headers(DHCPPacket *packet, be32_t source_addr,
                                   uint16_t source_port, be32_t destination_addr,
                                   uint16_t destination_port, uint16_t len, int ip_service_type) {
        packet->ip.version = IPVERSION;
        packet->ip.ihl = DHCP_IP_SIZE / 4;
        packet->ip.tot_len = htobe16(len);

        if (ip_service_type >= 0)
                packet->ip.tos = ip_service_type;
        else
                packet->ip.tos = IPTOS_CLASS_CS6;

        packet->ip.protocol = IPPROTO_UDP;
        packet->ip.saddr = source_addr;
        packet->ip.daddr = destination_addr;

        packet->udp.source = htobe16(source_port);
        packet->udp.dest = htobe16(destination_port);

        packet->udp.len = htobe16(len - DHCP_IP_SIZE);

        packet->ip.check = packet->udp.len;
        packet->udp.check = dhcp_packet_checksum((uint8_t*)&packet->ip.ttl, len - 8);

        packet->ip.ttl = IPDEFTTL;
        packet->ip.check = 0;
        packet->ip.check = dhcp_packet_checksum((uint8_t*)&packet->ip, DHCP_IP_SIZE);
}

int dhcp_packet_verify_headers(DHCPPacket *packet, size_t len, bool checksum, uint16_t port) {
        size_t hdrlen;

        assert(packet);
        assert(len >= sizeof(DHCPPacket));

        /* IP */

        if (packet->ip.version != IPVERSION)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: not IPv4");

        if (packet->ip.ihl < 5)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: IPv4 IHL (%i words) invalid",
                                       packet->ip.ihl);

        hdrlen = packet->ip.ihl * 4;
        if (hdrlen < 20)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: IPv4 IHL (%zu bytes) smaller than minimum (20 bytes)",
                                       hdrlen);

        if (len < hdrlen)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: packet (%zu bytes) smaller than expected (%zu) by IP header",
                                       len, hdrlen);

        /* UDP */

        if (packet->ip.protocol != IPPROTO_UDP)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: not UDP");

        if (len < hdrlen + be16toh(packet->udp.len))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: packet (%zu bytes) smaller than expected (%zu) by UDP header",
                                       len, hdrlen + be16toh(packet->udp.len));

        if (be16toh(packet->udp.dest) != port)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: to port %u, which is not the DHCP client port (%u)",
                                       be16toh(packet->udp.dest), port);

        /* checksums - computing these is relatively expensive, so only do it
           if all the other checks have passed
         */

        if (dhcp_packet_checksum((uint8_t*)&packet->ip, hdrlen))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "ignoring packet: invalid IP checksum");

        if (checksum && packet->udp.check) {
                packet->ip.check = packet->udp.len;
                packet->ip.ttl = 0;

                if (dhcp_packet_checksum((uint8_t*)&packet->ip.ttl,
                                  be16toh(packet->udp.len) + 12))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "ignoring packet: invalid UDP checksum");
        }

        return 0;
}
