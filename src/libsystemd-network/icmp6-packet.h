/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <netinet/in.h>

#include "macro.h"
#include "time-util.h"

typedef struct ICMP6Pakcet {
        unsigned n_ref;

        struct in6_addr sender_address;
        struct triple_timestamp timestamp;

        size_t raw_size;
        uint8_t raw_packet[];
} ICMP6Packet;

ICMP6Packet* icmp6_packet_ref(ICMP6Packet *p);
ICMP6Packet* icmp6_packet_unref(ICMP6Packet *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(ICMP6Packet*, icmp6_packet_unref);

/* IPv6 Header is 40 bytes and reserves 2 bytes to represent the Payload Length. Thus, the max payload size,
 * including extension headers, is 65535 bytes (2^16 - 1). Jumbograms can be larger (2^32 - 1). */
#define ICMP6_MAX_NORMAL_PAYLOAD_SIZE 65535

int icmp6_packet_set_sender_address(ICMP6Packet *p, const struct in6_addr *addr);
int icmp6_packet_get_sender_address(ICMP6Packet *p, struct in6_addr *ret);
int icmp6_packet_get_timestamp(ICMP6Packet *p, clockid_t clock, usec_t *ret);
const struct icmp6_hdr* icmp6_packet_get_header(ICMP6Packet *p);
int icmp6_packet_get_type(ICMP6Packet *p);

int icmp6_packet_receive(int fd, ICMP6Packet **ret);
