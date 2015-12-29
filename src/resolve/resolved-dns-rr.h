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

#include <netinet/in.h>

#include "bitmap.h"
#include "dns-type.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "list.h"

typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsTxtItem DnsTxtItem;

/* DNSKEY RR flags */
#define DNSKEY_FLAG_ZONE_KEY (UINT16_C(1) << 8)
#define DNSKEY_FLAG_SEP      (UINT16_C(1) << 0)

/* mDNS RR flags */
#define MDNS_RR_CACHE_FLUSH  (UINT16_C(1) << 15)

/* DNSSEC algorithm identifiers, see
 * http://tools.ietf.org/html/rfc4034#appendix-A.1 and
 * https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml */
enum {
        DNSSEC_ALGORITHM_RSAMD5 = 1,
        DNSSEC_ALGORITHM_DH,
        DNSSEC_ALGORITHM_DSA,
        DNSSEC_ALGORITHM_ECC,
        DNSSEC_ALGORITHM_RSASHA1,
        DNSSEC_ALGORITHM_DSA_NSEC3_SHA1,
        DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1,
        DNSSEC_ALGORITHM_RSASHA256 = 8,        /* RFC 5702 */
        DNSSEC_ALGORITHM_RSASHA512 = 10,       /* RFC 5702 */
        DNSSEC_ALGORITHM_ECC_GOST = 12,        /* RFC 5933 */
        DNSSEC_ALGORITHM_ECDSAP256SHA256 = 13, /* RFC 6605 */
        DNSSEC_ALGORITHM_ECDSAP384SHA384 = 14, /* RFC 6605 */
        DNSSEC_ALGORITHM_INDIRECT = 252,
        DNSSEC_ALGORITHM_PRIVATEDNS,
        DNSSEC_ALGORITHM_PRIVATEOID,
        _DNSSEC_ALGORITHM_MAX_DEFINED
};

/* DNSSEC digest identifiers, see
 * https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml */
enum {
        DNSSEC_DIGEST_SHA1 = 1,
        DNSSEC_DIGEST_SHA256 = 2,              /* RFC 4509 */
        DNSSEC_DIGEST_GOST_R_34_11_94 = 3,     /* RFC 5933 */
        DNSSEC_DIGEST_SHA384 = 4,              /* RFC 6605 */
        _DNSSEC_DIGEST_MAX_DEFINED
};

struct DnsResourceKey {
        unsigned n_ref;
        uint16_t class, type;
        char *_name; /* don't access directy, use DNS_RESOURCE_KEY_NAME()! */
};

/* Creates a temporary resource key. This is only useful to quickly
 * look up something, without allocating a full DnsResourceKey object
 * for it. Note that it is not OK to take references to this kind of
 * resource key object. */
#define DNS_RESOURCE_KEY_CONST(c, t, n)                 \
        ((DnsResourceKey) {                             \
                .n_ref = (unsigned) -1,                 \
                .class = c,                             \
                .type = t,                              \
                ._name = (char*) n,                     \
        })


struct DnsTxtItem {
        size_t length;
        LIST_FIELDS(DnsTxtItem, items);
        uint8_t data[];
};

struct DnsResourceRecord {
        unsigned n_ref;
        DnsResourceKey *key;
        char *to_string;
        uint32_t ttl;
        usec_t expiry; /* RRSIG signature expiry */
        bool unparseable:1;
        bool wire_format_canonical:1;
        void *wire_format;
        size_t wire_format_size;
        size_t wire_format_rdata_offset;
        union {
                struct {
                        void *data;
                        size_t size;
                } generic, opt;

                struct {
                        uint16_t priority;
                        uint16_t weight;
                        uint16_t port;
                        char *name;
                } srv;

                struct {
                        char *name;
                } ptr, ns, cname, dname;

                struct {
                        char *cpu;
                        char *os;
                } hinfo;

                struct {
                        DnsTxtItem *items;
                } txt, spf;

                struct {
                        struct in_addr in_addr;
                } a;

                struct {
                        struct in6_addr in6_addr;
                } aaaa;

                struct {
                        char *mname;
                        char *rname;
                        uint32_t serial;
                        uint32_t refresh;
                        uint32_t retry;
                        uint32_t expire;
                        uint32_t minimum;
                } soa;

                struct {
                        uint16_t priority;
                        char *exchange;
                } mx;

                struct {
                        uint8_t version;
                        uint8_t size;
                        uint8_t horiz_pre;
                        uint8_t vert_pre;
                        uint32_t latitude;
                        uint32_t longitude;
                        uint32_t altitude;
                } loc;

                struct {
                        uint16_t key_tag;
                        uint8_t algorithm;
                        uint8_t digest_type;
                        void *digest;
                        size_t digest_size;
                } ds;

                /* https://tools.ietf.org/html/rfc4255#section-3.1 */
                struct {
                        uint8_t algorithm;
                        uint8_t fptype;
                        void *fingerprint;
                        size_t fingerprint_size;
                } sshfp;

                /* http://tools.ietf.org/html/rfc4034#section-2.1 */
                struct {
                        uint16_t flags;
                        uint8_t protocol;
                        uint8_t algorithm;
                        void* key;
                        size_t key_size;
                } dnskey;

                /* http://tools.ietf.org/html/rfc4034#section-3.1 */
                struct {
                        uint16_t type_covered;
                        uint8_t algorithm;
                        uint8_t labels;
                        uint32_t original_ttl;
                        uint32_t expiration;
                        uint32_t inception;
                        uint16_t key_tag;
                        char *signer;
                        void *signature;
                        size_t signature_size;
                } rrsig;

                /* https://tools.ietf.org/html/rfc4034#section-4.1 */
                struct {
                        char *next_domain_name;
                        Bitmap *types;
                } nsec;

                struct {
                        uint8_t algorithm;
                        uint8_t flags;
                        uint16_t iterations;
                        void *salt;
                        size_t salt_size;
                        void *next_hashed_name;
                        size_t next_hashed_name_size;
                        Bitmap *types;
                } nsec3;
        };
};

static inline const char* DNS_RESOURCE_KEY_NAME(const DnsResourceKey *key) {
        if (_unlikely_(!key))
                return NULL;

        if (key->_name)
                return key->_name;

        return (char*) key + sizeof(DnsResourceKey);
}

DnsResourceKey* dns_resource_key_new(uint16_t class, uint16_t type, const char *name);
DnsResourceKey* dns_resource_key_new_redirect(const DnsResourceKey *key, const DnsResourceRecord *cname);
int dns_resource_key_new_append_suffix(DnsResourceKey **ret, DnsResourceKey *key, char *name);
DnsResourceKey* dns_resource_key_new_consume(uint16_t class, uint16_t type, char *name);
DnsResourceKey* dns_resource_key_ref(DnsResourceKey *key);
DnsResourceKey* dns_resource_key_unref(DnsResourceKey *key);
bool dns_resource_key_is_address(const DnsResourceKey *key);
int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b);
int dns_resource_key_match_rr(const DnsResourceKey *key, DnsResourceRecord *rr, const char *search_domain);
int dns_resource_key_match_cname_or_dname(const DnsResourceKey *key, const DnsResourceKey *cname, const char *search_domain);
int dns_resource_key_match_soa(const DnsResourceKey *key, const DnsResourceKey *soa);
int dns_resource_key_to_string(const DnsResourceKey *key, char **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceKey*, dns_resource_key_unref);

static inline bool dns_key_is_shared(const DnsResourceKey *key) {
        return IN_SET(key->type, DNS_TYPE_PTR);
}

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key);
DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name);
DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr);
DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr);
int dns_resource_record_new_reverse(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_new_address(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b);
const char* dns_resource_record_to_string(DnsResourceRecord *rr);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceRecord*, dns_resource_record_unref);

int dns_resource_record_to_wire_format(DnsResourceRecord *rr, bool canonical);

DnsTxtItem *dns_txt_item_free_all(DnsTxtItem *i);
bool dns_txt_item_equal(DnsTxtItem *a, DnsTxtItem *b);

extern const struct hash_ops dns_resource_key_hash_ops;

const char* dnssec_algorithm_to_string(int i) _const_;
int dnssec_algorithm_from_string(const char *s) _pure_;

const char *dnssec_digest_to_string(int i) _const_;
int dnssec_digest_from_string(const char *s) _pure_;
