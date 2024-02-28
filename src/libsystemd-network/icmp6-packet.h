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

int icmp6_packet_get_sender_address(ICMP6Packet *p, struct in6_addr *ret);
int icmp6_packet_get_timestamp(ICMP6Packet *p, clockid_t clock, usec_t *ret);
int icmp6_packet_get_type(ICMP6Packet *p);

int icmp6_packet_receive(int fd, ICMP6Packet **ret);
