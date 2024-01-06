/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "hashmap.h"
#include "in-addr-util.h"
#include "macro.h"
#include "sparse-endian.h"

typedef struct DnsPacketHeader DnsPacketHeader;
typedef struct DnsPacket DnsPacket;

#include "resolved-def.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-question.h"
#include "resolved-dns-rr.h"

typedef enum DnsProtocol {
        DNS_PROTOCOL_DNS,
        DNS_PROTOCOL_MDNS,
        DNS_PROTOCOL_LLMNR,
        _DNS_PROTOCOL_MAX,
        _DNS_PROTOCOL_INVALID = -EINVAL,
} DnsProtocol;

struct DnsPacketHeader {
        uint16_t id;
        be16_t flags;
        be16_t qdcount;
        be16_t ancount;
        be16_t nscount;
        be16_t arcount;
} _packed_;

#define DNS_PACKET_HEADER_SIZE sizeof(DnsPacketHeader)
#define UDP4_PACKET_HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define UDP6_PACKET_HEADER_SIZE (sizeof(struct ip6_hdr) + sizeof(struct udphdr))

assert_cc(sizeof(struct ip6_hdr) == 40);
assert_cc(sizeof(struct iphdr) == 20);
assert_cc(sizeof(struct udphdr) == 8);
assert_cc(sizeof(DnsPacketHeader) == 12);

/* The various DNS protocols deviate in how large a packet can grow, but the TCP transport has a 16-bit size
 * field, hence that appears to be the absolute maximum. */
#define DNS_PACKET_SIZE_MAX 0xFFFFu

/* The default size to use for allocation when we don't know how large
 * the packet will turn out to be. */
#define DNS_PACKET_SIZE_START 512u

/* RFC 1035 say 512 is the maximum, for classic unicast DNS */
#define DNS_PACKET_UNICAST_SIZE_MAX 512u

/* With EDNS0 we can use larger packets, default to 1232, which is what is commonly used */
#define DNS_PACKET_UNICAST_SIZE_LARGE_MAX 1232u

struct DnsPacket {
        unsigned n_ref;
        DnsProtocol protocol;
        size_t size, allocated, rindex, max_size, fragsize;
        void *_data; /* don't access directly, use DNS_PACKET_DATA()! */
        Hashmap *names; /* For name compression */
        size_t opt_start, opt_size;

        /* Parsed data */
        DnsQuestion *question;
        DnsAnswer *answer;
        DnsResourceRecord *opt;

        /* For support of truncated packets */
        DnsPacket *more;

        /* Packet reception metadata */
        usec_t timestamp; /* CLOCK_BOOTTIME (or CLOCK_MONOTONIC if the former doesn't exist) */
        int ifindex;
        int family, ipproto;
        union in_addr_union sender, destination;
        uint16_t sender_port, destination_port;
        uint32_t ttl;

        bool on_stack;
        bool extracted;
        bool refuse_compression;
        bool canonical_form;

        /* Note: fields should be ordered to minimize alignment gaps. Use pahole! */
};

static inline uint8_t* DNS_PACKET_DATA(const DnsPacket *p) {
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

#define DNS_PACKET_FLAG_TC (UINT16_C(1) << 9)

static inline uint16_t DNS_PACKET_RCODE(DnsPacket *p) {
        uint16_t rcode;

        if (p->opt)
                rcode = (uint16_t) (p->opt->ttl >> 24);
        else
                rcode = 0;

        return rcode | (be16toh(DNS_PACKET_HEADER(p)->flags) & 0xF);
}

static inline uint16_t DNS_PACKET_PAYLOAD_SIZE_MAX(DnsPacket *p) {

        /* Returns the advertised maximum size for replies, or the DNS default if there's nothing defined. */

        if (p->ipproto == IPPROTO_TCP) /* we ignore EDNS(0) size data on TCP, like everybody else */
                return DNS_PACKET_SIZE_MAX;

        if (p->opt)
                return MAX(DNS_PACKET_UNICAST_SIZE_MAX, p->opt->key->class);

        return DNS_PACKET_UNICAST_SIZE_MAX;
}

static inline bool DNS_PACKET_DO(DnsPacket *p) {
        if (!p->opt)
                return false;

        return !!(p->opt->ttl & (1U << 15));
}

static inline bool DNS_PACKET_VERSION_SUPPORTED(DnsPacket *p) {
        /* Returns true if this packet is in a version we support. Which means either non-EDNS or EDNS(0), but not EDNS
         * of any newer versions */

        if (!p->opt)
                return true;

        return DNS_RESOURCE_RECORD_OPT_VERSION_SUPPORTED(p->opt);
}

static inline bool DNS_PACKET_IS_FRAGMENTED(DnsPacket *p) {
        assert(p);

        /* For ingress packets: was this packet fragmented according to our knowledge? */

        return p->fragsize != 0;
}

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

int dns_packet_new(DnsPacket **p, DnsProtocol protocol, size_t min_alloc_dsize, size_t max_size);
int dns_packet_new_query(DnsPacket **p, DnsProtocol protocol, size_t min_alloc_dsize, bool dnssec_checking_disabled);

int dns_packet_dup(DnsPacket **ret, DnsPacket *p);

void dns_packet_set_flags(DnsPacket *p, bool dnssec_checking_disabled, bool truncated);

DnsPacket *dns_packet_ref(DnsPacket *p);
DnsPacket *dns_packet_unref(DnsPacket *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsPacket*, dns_packet_unref);

#define DNS_PACKET_REPLACE(a, b)                \
        do {                                    \
                typeof(a)* _a = &(a);           \
                typeof(b) _b = (b);             \
                dns_packet_unref(*_a);          \
                *_a = _b;                       \
        } while(0)

int dns_packet_validate(DnsPacket *p);
int dns_packet_validate_reply(DnsPacket *p);
int dns_packet_validate_query(DnsPacket *p);

int dns_packet_is_reply_for(DnsPacket *p, const DnsResourceKey *key);

int dns_packet_append_blob(DnsPacket *p, const void *d, size_t sz, size_t *start);
int dns_packet_append_uint8(DnsPacket *p, uint8_t v, size_t *start);
int dns_packet_append_uint16(DnsPacket *p, uint16_t v, size_t *start);
int dns_packet_append_uint32(DnsPacket *p, uint32_t v, size_t *start);
int dns_packet_append_string(DnsPacket *p, const char *s, size_t *start);
int dns_packet_append_raw_string(DnsPacket *p, const void *s, size_t size, size_t *start);
int dns_packet_append_label(DnsPacket *p, const char *s, size_t l, bool canonical_candidate, size_t *start);
int dns_packet_append_name(DnsPacket *p, const char *name, bool allow_compression, bool canonical_candidate, size_t *start);
int dns_packet_append_key(DnsPacket *p, const DnsResourceKey *key, const DnsAnswerFlags flags, size_t *start);
int dns_packet_append_rr(DnsPacket *p, const DnsResourceRecord *rr, const DnsAnswerFlags flags, size_t *start, size_t *rdata_start);
int dns_packet_append_opt(DnsPacket *p, uint16_t max_udp_size, bool edns0_do, bool include_rfc6975, const char *nsid, int rcode, size_t *ret_start);
int dns_packet_append_question(DnsPacket *p, DnsQuestion *q);
int dns_packet_append_answer(DnsPacket *p, DnsAnswer *a, unsigned *completed);

int dns_packet_patch_max_udp_size(DnsPacket *p, uint16_t max_udp_size);
int dns_packet_patch_ttls(DnsPacket *p, usec_t timestamp);

void dns_packet_truncate(DnsPacket *p, size_t sz);
int dns_packet_truncate_opt(DnsPacket *p);

int dns_packet_read(DnsPacket *p, size_t sz, const void **ret, size_t *start);
int dns_packet_read_blob(DnsPacket *p, void *d, size_t sz, size_t *start);
int dns_packet_read_uint8(DnsPacket *p, uint8_t *ret, size_t *start);
int dns_packet_read_uint16(DnsPacket *p, uint16_t *ret, size_t *start);
int dns_packet_read_uint32(DnsPacket *p, uint32_t *ret, size_t *start);
int dns_packet_read_string(DnsPacket *p, char **ret, size_t *start);
int dns_packet_read_raw_string(DnsPacket *p, const void **ret, size_t *size, size_t *start);
int dns_packet_read_name(DnsPacket *p, char **ret, bool allow_compression, size_t *start);
int dns_packet_read_key(DnsPacket *p, DnsResourceKey **ret, bool *ret_cache_flush_or_qu, size_t *start);
int dns_packet_read_rr(DnsPacket *p, DnsResourceRecord **ret, bool *ret_cache_flush, size_t *start);

void dns_packet_rewind(DnsPacket *p, size_t idx);

int dns_packet_skip_question(DnsPacket *p);
int dns_packet_extract(DnsPacket *p);

bool dns_packet_equal(const DnsPacket *a, const DnsPacket *b);

int dns_packet_ede_rcode(DnsPacket *p, char **ret_ede_msg);
bool dns_ede_rcode_is_dnssec(int ede_rcode);
int dns_packet_has_nsid_request(DnsPacket *p);

/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6 */
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
        DNS_RCODE_BADCOOKIE = 23,
        _DNS_RCODE_MAX_DEFINED,
        _DNS_RCODE_MAX = 4095 /* 4 bit rcode in the header plus 8 bit rcode in OPT, makes 12 bit */
};

/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11 */
enum {
        DNS_EDNS_OPT_RESERVED = 0,       /* RFC 6891 */
        DNS_EDNS_OPT_LLQ = 1,            /* RFC 8764 */
        DNS_EDNS_OPT_UL = 2,
        DNS_EDNS_OPT_NSID = 3,           /* RFC 5001 */
        /* DNS_EDNS_OPT_RESERVED = 4 */
        DNS_EDNS_OPT_DAU = 5,            /* RFC 6975 */
        DNS_EDNS_OPT_DHU = 6,            /* RFC 6975 */
        DNS_EDNS_OPT_N3U = 7,            /* RFC 6975 */
        DNS_EDNS_OPT_CLIENT_SUBNET = 8,  /* RFC 7871 */
        DNS_EDNS_OPT_EXPIRE = 9,         /* RFC 7314 */
        DNS_EDNS_OPT_COOKIE = 10,        /* RFC 7873 */
        DNS_EDNS_OPT_TCP_KEEPALIVE = 11, /* RFC 7828 */
        DNS_EDNS_OPT_PADDING = 12,       /* RFC 7830 */
        DNS_EDNS_OPT_CHAIN = 13,         /* RFC 7901 */
        DNS_EDNS_OPT_KEY_TAG = 14,       /* RFC 8145 */
        DNS_EDNS_OPT_EXT_ERROR = 15,     /* RFC 8914 */
        DNS_EDNS_OPT_CLIENT_TAG = 16,
        DNS_EDNS_OPT_SERVER_TAG = 17,
        _DNS_EDNS_OPT_MAX_DEFINED,
        _DNS_EDNS_OPT_INVALID = -EINVAL
};

/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes */
enum {
        DNS_EDE_RCODE_OTHER = 0,                    /* RFC 8914, Section 4.1 */
        DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG = 1,   /* RFC 8914, Section 4.2 */
        DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST = 2,    /* RFC 8914, Section 4.3 */
        DNS_EDE_RCODE_STALE_ANSWER = 3,             /* RFC 8914, Section 4.4 */
        DNS_EDE_RCODE_FORGED_ANSWER = 4,            /* RFC 8914, Section 4.5 */
        DNS_EDE_RCODE_DNSSEC_INDETERMINATE = 5,     /* RFC 8914, Section 4.6 */
        DNS_EDE_RCODE_DNSSEC_BOGUS = 6,             /* RFC 8914, Section 4.7 */
        DNS_EDE_RCODE_SIG_EXPIRED = 7,              /* RFC 8914, Section 4.8 */
        DNS_EDE_RCODE_SIG_NOT_YET_VALID = 8,        /* RFC 8914, Section 4.9 */
        DNS_EDE_RCODE_DNSKEY_MISSING = 9,           /* RFC 8914, Section 4.10 */
        DNS_EDE_RCODE_RRSIG_MISSING = 10,           /* RFC 8914, Section 4.11 */
        DNS_EDE_RCODE_NO_ZONE_KEY_BIT = 11,         /* RFC 8914, Section 4.12 */
        DNS_EDE_RCODE_NSEC_MISSING = 12,            /* RFC 8914, Section 4.13 */
        DNS_EDE_RCODE_CACHED_ERROR = 13,            /* RFC 8914, Section 4.14 */
        DNS_EDE_RCODE_NOT_READY = 14,               /* RFC 8914, Section 4.15 */
        DNS_EDE_RCODE_BLOCKED = 15,                 /* RFC 8914, Section 4.16 */
        DNS_EDE_RCODE_CENSORED = 16,                /* RFC 8914, Section 4.17 */
        DNS_EDE_RCODE_FILTERED = 17,                /* RFC 8914, Section 4.18 */
        DNS_EDE_RCODE_PROHIBITIED = 18,             /* RFC 8914, Section 4.19 */
        DNS_EDE_RCODE_STALE_NXDOMAIN_ANSWER = 19,   /* RFC 8914, Section 4.20 */
        DNS_EDE_RCODE_NOT_AUTHORITATIVE = 20,       /* RFC 8914, Section 4.21 */
        DNS_EDE_RCODE_NOT_SUPPORTED = 21,           /* RFC 8914, Section 4.22 */
        DNS_EDE_RCODE_UNREACH_AUTHORITY = 22,       /* RFC 8914, Section 4.23 */
        DNS_EDE_RCODE_NET_ERROR = 23,               /* RFC 8914, Section 4.24 */
        DNS_EDE_RCODE_INVALID_DATA = 24,            /* RFC 8914, Section 4.25 */
        DNS_EDE_RCODE_SIG_NEVER = 25,
        DNS_EDE_RCODE_TOO_EARLY = 26,               /* RFC 9250 */
        DNS_EDE_RCODE_UNSUPPORTED_NSEC3_ITER = 27,  /* RFC 9276 */
        DNS_EDE_RCODE_TRANSPORT_POLICY = 28,
        DNS_EDE_RCODE_SYNTHESIZED = 29,
        _DNS_EDE_RCODE_MAX_DEFINED,
        _DNS_EDE_RCODE_INVALID = -EINVAL
};

const char* dns_rcode_to_string(int i) _const_;
int dns_rcode_from_string(const char *s) _pure_;
const char *format_dns_rcode(int i, char buf[static DECIMAL_STR_MAX(int)]);
#define FORMAT_DNS_RCODE(i) format_dns_rcode(i, (char [DECIMAL_STR_MAX(int)]) {})

const char* dns_ede_rcode_to_string(int i) _const_;
const char *format_dns_ede_rcode(int i, char buf[static DECIMAL_STR_MAX(int)]);
#define FORMAT_DNS_EDE_RCODE(i) format_dns_ede_rcode(i, (char [DECIMAL_STR_MAX(int)]) {})

const char* dns_protocol_to_string(DnsProtocol p) _const_;
DnsProtocol dns_protocol_from_string(const char *s) _pure_;

/* https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml#dns-svcparamkeys */
enum {
        DNS_SVC_PARAM_KEY_MANDATORY = 0, /* RFC 9460, section 8 */
        DNS_SVC_PARAM_KEY_ALPN = 1, /* RFC 9460 section 7.1 */
        DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN = 2, /* RFC 9460, Section 7.1 */
        DNS_SVC_PARAM_KEY_PORT = 3, /* RFC 9460 section 7.2 */
        DNS_SVC_PARAM_KEY_IPV4HINT = 4, /* RFC 9460 section 7.3 */
        DNS_SVC_PARAM_KEY_ECH = 5, /* RFC 9460 */
        DNS_SVC_PARAM_KEY_IPV6HINT = 6, /* RFC 9460 section 7.3 */
        DNS_SVC_PARAM_KEY_DOHPATH = 7, /* RFC 9461 */
        DNS_SVC_PARAM_KEY_OHTTP = 8,
        _DNS_SVC_PARAM_KEY_MAX_DEFINED,
        DNS_SVC_PARAM_KEY_INVALID = 65535 /* RFC 9460 */
};

const char* dns_svc_param_key_to_string(int i) _const_;
const char *format_dns_svc_param_key(uint16_t i, char buf[static DECIMAL_STR_MAX(uint16_t)+3]);
#define FORMAT_DNS_SVC_PARAM_KEY(i) format_dns_svc_param_key(i, (char [DECIMAL_STR_MAX(uint16_t)+3]) {})

#define LLMNR_MULTICAST_IPV4_ADDRESS ((struct in_addr) { .s_addr = htobe32(224U << 24 | 252U) })
#define LLMNR_MULTICAST_IPV6_ADDRESS ((struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03 } })

#define MDNS_MULTICAST_IPV4_ADDRESS  ((struct in_addr) { .s_addr = htobe32(224U << 24 | 251U) })
#define MDNS_MULTICAST_IPV6_ADDRESS  ((struct in6_addr) { .s6_addr = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb } })

extern const struct hash_ops dns_packet_hash_ops;

static inline uint64_t SD_RESOLVED_FLAGS_MAKE(
                DnsProtocol protocol,
                int family,
                bool authenticated,
                bool confidential) {
        uint64_t f;

        /* Converts a protocol + family into a flags field as used in queries and responses */

        f = (authenticated ? SD_RESOLVED_AUTHENTICATED : 0) |
                (confidential ? SD_RESOLVED_CONFIDENTIAL : 0);

        switch (protocol) {
        case DNS_PROTOCOL_DNS:
                return f|SD_RESOLVED_DNS;

        case DNS_PROTOCOL_LLMNR:
                return f|(family == AF_INET6 ? SD_RESOLVED_LLMNR_IPV6 : SD_RESOLVED_LLMNR_IPV4);

        case DNS_PROTOCOL_MDNS:
                return f|(family == AF_INET6 ? SD_RESOLVED_MDNS_IPV6 : SD_RESOLVED_MDNS_IPV4);

        default:
                return f;
        }
}

static inline size_t dns_packet_size_max(DnsPacket *p) {
        assert(p);

        /* Why not insist on a fully initialized max_size during DnsPacket construction? Well, this way it's easy to
         * allocate a transient, throw-away DnsPacket on the stack by simple zero initialization, without having to
         * deal with explicit field initialization. */

        return p->max_size != 0 ? p->max_size : DNS_PACKET_SIZE_MAX;
}

static inline size_t udp_header_size(int af) {

        switch (af) {
        case AF_INET:
                return UDP4_PACKET_HEADER_SIZE;
        case AF_INET6:
                return UDP6_PACKET_HEADER_SIZE;
        default:
                assert_not_reached();
        }
}

size_t dns_packet_size_unfragmented(DnsPacket *p);
