/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation. All rights reserved.
***/

#include <net/if_arp.h>

#include "dhcp-option.h"
#include "dhcp-packet.h"
#include "ip-util.h"
#include "memory-util.h"

#define DHCP_CLIENT_MIN_OPTIONS_SIZE            312

int bootp_message_init(
                DHCPMessage *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                uint8_t hlen,
                const uint8_t *chaddr) {

        assert(message);
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

        return 0;
}

int dhcp_message_init(
                DHCPMessage *message,
                uint8_t op,
                uint32_t xid,
                uint16_t arp_type,
                uint8_t hlen,
                const uint8_t *chaddr,
                uint8_t type,
                size_t optlen,
                size_t *ret_optoffset) {

        size_t offset = 0;
        int r;

        assert(message);
        assert(chaddr || hlen == 0);
        assert(ret_optoffset);

        r = bootp_message_init(message, op, xid, arp_type, hlen, chaddr);
        if (r < 0)
                return r;

        r = dhcp_option_append(message, optlen, &offset, 0,
                               SD_DHCP_OPTION_MESSAGE_TYPE, 1, &type);
        if (r < 0)
                return r;

        *ret_optoffset = offset;
        return 0;
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
        packet->udp.check = ip_checksum(&packet->ip.ttl, len - 8);

        packet->ip.ttl = IPDEFTTL;
        packet->ip.check = 0;
        packet->ip.check = ip_checksum(&packet->ip, DHCP_IP_SIZE);
}
