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

#include <netinet/udp.h>
#include <netinet/ip.h>

#include "macro.h"
#include "sparse-endian.h"
#include "hashmap.h"
#include "in-addr-util.h"

typedef struct DnsPacketHeader DnsPacketHeader;
typedef struct DnsPacket DnsPacket;

#include "resolved-dns-rr.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"
#include "resolved-def.h"

typedef enum DnsProtocol {
        DNS_PROTOCOL_DNS,
        DNS_PROTOCOL_MDNS,
        DNS_PROTOCOL_LLMNR,
        _DNS_PROTOCOL_MAX,
        _DNS_PROTOCOL_INVALID = -1
} DnsProtocol;

struct DnsPacketHeader {
        uint16_t id;
        be16_t flags;
        be16_t qdcount;
        be16_t ancount;
        be16_t nscount;
        be16_t arcount;
};

#define DNS_PACKET_HEADER_SIZE sizeof(DnsPacketHeader)
#define UDP_PACKET_HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))

/* The various DNS protocols deviate in how large a packet can grow,
   but the TCP transport has a 16bit size field, hence that appears to
   be the absolute maximum. */
#define DNS_PACKET_SIZE_MAX 0xFFFF

/* RFC 1035 say 512 is the maximum, for classic unicast DNS */
#define DNS_PACKET_UNICAST_SIZE_MAX 512

#define DNS_PACKET_SIZE_START 512

struct DnsPacket {
        int n_ref;
        DnsProtocol protocol;
        size_t size, allocated, rindex;
        void *_data; /* don't access directly, use DNS_PACKET_DATA()! */
        Hashmap *names; /* For name compression */

        /* Parsed data */
        DnsQuestion *question;
        DnsAnswer *answer;

        /* Packet reception metadata */
        int ifindex;
        int family, ipproto;
        union in_addr_union sender, destination;
        uint16_t sender_port, destination_port;
        uint32_t ttl;

        bool extracted;
        bool refuse_compression;
};

static inline uint8_t* DNS_PACKET_DATA(DnsPacket *p) {
        if (_unlikely_(!p))
                return NULL;

        if (p->_data)
                return p->_data;

        return ((uint8_t*) p) + ALIGN(sizeof(DnsPacket));
}

#define DNS_PACKET_HEADER(p) ((DnsPacketHeader*) DNS_PACKET_DATA(p))
#define DNS_PACKET_ID(p) DNS_PACKET_HEADER(p)->id
#define DNS_PACKET_QR(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 15) & 1)
#define DNS_PACKET_OPCODE(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 11) & 15)
#define DNS_PACKET_AA(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 10) & 1)
#define DNS_PACKET_TC(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 9) & 1)
#define DNS_PACKET_RD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 8) & 1)
#define DNS_PACKET_RA(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 7) & 1)
#define DNS_PACKET_AD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 5) & 1)
#define DNS_PACKET_CD(p) ((be16toh(DNS_PACKET_HEADER(p)->flags) >> 4) & 1)
#define DNS_PACKET_RCODE(p) (be16toh(DNS_PACKET_HEADER(p)->flags) & 15)

/* LLMNR defines some bits differently */
#define DNS_PACKET_LLMNR_C(p) DNS_PACKET_AA(p)
#define DNS_PACKET_LLMNR_T(p) DNS_PACKET_RD(p)

#define DNS_PACKET_QDCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->qdcount)
#define DNS_PACKET_ANCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->ancount)
#define DNS_PACKET_NSCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->nscount)
#define DNS_PACKET_ARCOUNT(p) be16toh(DNS_PACKET_HEADER(p)->arcount)

#define DNS_PACKET_MAKE_FLAGS(qr, opcode, aa, tc, rd, ra, ad, cd, rcode) \
        (((uint16_t) !!(qr) << 15) |                                    \
         ((uint16_t) ((opcode) & 15) << 11) |                           \
         ((uint16_t) !!(aa) << 10) |                /* on LLMNR: c */   \
         ((uint16_t) !!(tc) << 9) |                                     \
         ((uint16_t) !!(rd) << 8) |                 /* on LLMNR: t */   \
         ((uint16_t) !!(ra) << 7) |                                     \
         ((uint16_t) !!(ad) << 5) |                                     \
         ((uint16_t) !!(cd) << 4) |                                     \
         ((uint16_t) ((rcode) & 15)))

static inline unsigned DNS_PACKET_RRCOUNT(DnsPacket *p) {
        return
                (unsigned) DNS_PACKET_ANCOUNT(p) +
                (unsigned) DNS_PACKET_NSCOUNT(p) +
                (unsigned) DNS_PACKET_ARCOUNT(p);
}

int dns_packet_new(DnsPacket **p, DnsProtocol protocol, size_t mtu);
int dns_packet_new_query(DnsPacket **p, DnsProtocol protocol, size_t mtu);

DnsPacket *dns_packet_ref(DnsPacket *p);
DnsPacket *dns_packet_unref(DnsPacket *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsPacket*, dns_packet_unref);

int dns_packet_validate(DnsPacket *p);
int dns_packet_validate_reply(DnsPacket *p);
int dns_packet_validate_query(DnsPacket *p);

int dns_packet_append_blob(DnsPacket *p, const void *d, size_t sz, size_t *start);
int dns_packet_append_uint8(DnsPacket *p, uint8_t v, size_t *start);
int dns_packet_append_uint16(DnsPacket *p, uint16_t v, size_t *start);
int dns_packet_append_uint32(DnsPacket *p, uint32_t v, size_t *start);
int dns_packet_append_string(DnsPacket *p, const char *s, size_t *start);
int dns_packet_append_label(DnsPacket *p, const char *s, size_t l, size_t *start);
int dns_packet_append_name(DnsPacket *p, const char *name,
                           bool allow_compression, size_t *start);
int dns_packet_append_key(DnsPacket *p, const DnsResourceKey *key, size_t *start);
int dns_packet_append_rr(DnsPacket *p, const DnsResourceRecord *rr, size_t *start);

int dns_packet_read(DnsPacket *p, size_t sz, const void **ret, size_t *start);
int dns_packet_read_blob(DnsPacket *p, void *d, size_t sz, size_t *start);
int dns_packet_read_uint8(DnsPacket *p, uint8_t *ret, size_t *start);
int dns_packet_read_uint16(DnsPacket *p, uint16_t *ret, size_t *start);
int dns_packet_read_uint32(DnsPacket *p, uint32_t *ret, size_t *start);
int dns_packet_read_string(DnsPacket *p, char **ret, size_t *start);
int dns_packet_read_name(DnsPacket *p, char **ret,
                         bool allow_compression, size_t *start);
int dns_packet_read_key(DnsPacket *p, DnsResourceKey **ret, size_t *start);
int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, size_t *start);

void dns_packet_rewind(DnsPacket *p, size_t idx);

int dns_packet_skip_question(DnsPacket *p);
int dns_packet_extract(DnsPacket *p);

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

const char* dns_protocol_to_string(DnsProtocol p) _const_;
DnsProtocol dns_protocol_from_string(const char *s) _pure_;

#define LLMNR_MULTICAST_IPV4_ADDRESS ((struct in_addr) { .s_addr = htobe32(224U << 24 | 252U) })
#define LLMNR_MULTICAST_IPV6_ADDRESS ((struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 } })

#define DNSKEY_FLAG_ZONE_KEY (1u << 8)
#define DNSKEY_FLAG_SEP      (1u << 0)

static inline uint16_t dnskey_to_flags(const DnsResourceRecord *rr) {
        return (rr->dnskey.zone_key_flag * DNSKEY_FLAG_ZONE_KEY |
                rr->dnskey.sep_flag * DNSKEY_FLAG_SEP);
}

/* http://tools.ietf.org/html/rfc4034#appendix-A.1 */
enum {
        DNSSEC_ALGORITHM_RSAMD5 = 1,
        DNSSEC_ALGORITHM_DH,
        DNSSEC_ALGORITHM_DSA,
        DNSSEC_ALGORITHM_ECC,
        DNSSEC_ALGORITHM_RSASHA1,
        DNSSEC_ALGORITHM_DSA_NSEC3_SHA1,
        DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
        DNSSEC_ALGORITHM_INDIRECT = 252,
        DNSSEC_ALGORITHM_PRIVATEDNS,
        DNSSEC_ALGORITHM_PRIVATEOID,
        _DNSSEC_ALGORITHM_MAX_DEFINED
};

const char* dnssec_algorithm_to_string(int i) _const_;
int dnssec_algorithm_from_string(const char *s) _pure_;

static inline uint64_t SD_RESOLVED_FLAGS_MAKE(DnsProtocol protocol, int family) {

        /* Converts a protocol + family into a flags field as used in queries */

        switch (protocol) {
        case DNS_PROTOCOL_DNS:
                return SD_RESOLVED_DNS;

        case DNS_PROTOCOL_LLMNR:
                return family == AF_INET6 ? SD_RESOLVED_LLMNR_IPV6 : SD_RESOLVED_LLMNR_IPV4;

        default:
                break;
        }

        return 0;
}
