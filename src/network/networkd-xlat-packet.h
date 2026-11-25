/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>

#include "forward.h"

/* Userspace translation of single IP packets for CLAT (RFC 7915), used by the TUN device backend. */

#define XLAT_PACKET_SIZE_MAX (UINT16_MAX + 40U)

typedef struct XlatPacketParams {
        struct in6_addr address;        /* CLAT IPv6 address */
        struct in6_addr pref64;         /* NAT64 prefix, masked to its length */
        uint8_t pref64_len;
        uint32_t mtu;                   /* MTU of the IPv6 link */
        bool drop_udp_zero_checksum;    /* drop IPv4 UDP datagrams without checksum */
        uint16_t ipv4_id;               /* generator of the IPv4 identification field */
} XlatPacketParams;

/* Both functions return 0 and the length of the translated packet on success, or a negative errno:
 *   -EBADMSG:    the packet is malformed, or its checksum is wrong
 *   -EOPNOTSUPP: the packet is valid, but of a kind that is not translated
 *   -EPERM:      an address must not be translated, or the packet is not for the translator
 *   -ENODATA:    a UDP datagram without checksum that must be dropped
 *   -ENOBUFS:    the output buffer is too small */
int xlat_packet_4to6(
                XlatPacketParams *params,
                const uint8_t *packet,
                size_t size,
                uint8_t *ret,
                size_t ret_max,
                size_t *ret_size,
                struct in6_addr *ret_destination);

/* checksum_partial must be set when the transport checksum of the packet was not completed yet, i.e. when it
 * was received with TP_STATUS_CSUMNOTREADY on a packet socket. */
int xlat_packet_6to4(
                XlatPacketParams *params,
                const uint8_t *packet,
                size_t size,
                bool checksum_partial,
                uint8_t *ret,
                size_t ret_max,
                size_t *ret_size);
