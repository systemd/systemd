/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

typedef struct DnsPacketHeader DnsPacketHeader;
typedef struct DnsPacket DnsPacket;

#include <inttypes.h>

#include "macro.h"
#include "sparse-endian.h"
#include "hashmap.h"
#include "resolved-dns-rr.h"

struct DnsPacketHeader {
        uint16_t id;
        be16_t flags;
        be16_t qdcount;
        be16_t ancount;
        be16_t nscount;
        be16_t arcount;
};

#define DNS_PACKET_HEADER_SIZE sizeof(DnsPacketHeader)
#define DNS_PACKET_SIZE_START 512

struct DnsPacket {
        int n_ref;
        size_t size, allocated, rindex;
        Hashmap *names; /* For name compression */
        void *data;
        int ifindex;
};

static inline uint8_t* DNS_PACKET_DATA(DnsPacket *p) {
        if (_unlikely_(!p))
                return NULL;

        if (p->data)
                return p->data;

        return ((uint8_t*) p) + ALIGN(sizeof(DnsPacket));
}

#define DNS_PACKET_HEADER(p) ((DnsPacketHeader*) DNS_PACKET_DATA(p))

int dns_packet_new(DnsPacket **p, size_t mtu);
int dns_packet_new_query(DnsPacket **p, size_t mtu);

DnsPacket *dns_packet_ref(DnsPacket *p);
DnsPacket *dns_packet_unref(DnsPacket *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsPacket*, dns_packet_unref);

int dns_packet_validate(DnsPacket *p);
int dns_packet_validate_reply(DnsPacket *p);

int dns_packet_append_uint8(DnsPacket *p, uint8_t v, size_t *start);
int dns_packet_append_uint16(DnsPacket *p, uint16_t v, size_t *start);
int dns_packet_append_string(DnsPacket *p, const char *s, size_t *start);
int dns_packet_append_label(DnsPacket *p, const char *s, size_t l, size_t *start);
int dns_packet_append_name(DnsPacket *p, const char *name, size_t *start);
int dns_packet_append_key(DnsPacket *p, const DnsResourceKey *k, size_t *start);

int dns_packet_read(DnsPacket *p, size_t sz, const void **ret, size_t *start);
int dns_packet_read_uint8(DnsPacket *p, uint8_t *ret, size_t *start);
int dns_packet_read_uint16(DnsPacket *p, uint16_t *ret, size_t *start);
int dns_packet_read_uint32(DnsPacket *p, uint32_t *ret, size_t *start);
int dns_packet_read_string(DnsPacket *p, char **ret, size_t *start);
int dns_packet_read_name(DnsPacket *p, char **ret, size_t *start);
int dns_packet_read_key(DnsPacket *p, DnsResourceKey *ret, size_t *start);
int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, size_t *start);

int dns_packet_skip_question(DnsPacket *p);

#define DNS_PACKET_MAKE_FLAGS(qr, opcode, aa, tc, rd, ra, ad, cd, rcode) \
        (((uint16_t) !!qr << 15) |  \
         ((uint16_t) (opcode & 15) << 11) | \
         ((uint16_t) !!aa << 10) | \
         ((uint16_t) !!tc << 9) | \
         ((uint16_t) !!rd << 8) | \
         ((uint16_t) !!ra << 7) | \
         ((uint16_t) !!ad << 5) | \
         ((uint16_t) !!cd << 4) | \
         ((uint16_t) (rcode & 15)))

#define DNS_PACKET_RCODE(p) (be16toh(DNS_PACKET_HEADER(p)->flags) & 15)

enum {
        DNS_RCODE_SUCCESS = 0,
        DNS_RCODE_FORMERR = 1,
        DNS_RCODE_SERVFAIL = 2,
        DNS_RCODE_NXDOMAIN = 3,
        DNS_RCODE_NOTIMP = 4,
        DNS_RCODE_REFUSED = 5,
        DNS_RCODE_YXDOMAIN = 6,
        DNS_RCODE_YXRRSET = 7,
        DNS_RCODE_NXRRSET = 8,
        DNS_RCODE_NOTAUTH = 9,
        DNS_RCODE_NOTZONE = 10,
        DNS_RCODE_BADVERS = 16,
        DNS_RCODE_BADSIG = 16, /* duplicate value! */
        DNS_RCODE_BADKEY = 17,
        DNS_RCODE_BADTIME = 18,
        DNS_RCODE_BADMODE = 19,
        DNS_RCODE_BADNAME = 20,
        DNS_RCODE_BADALG = 21,
        DNS_RCODE_BADTRUNC = 22,
        _DNS_RCODE_MAX_DEFINED
};

const char* dns_rcode_to_string(int i) _const_;
int dns_rcode_from_string(const char *s) _pure_;
