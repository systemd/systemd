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
#include "hashmap.h"
#include "in-addr-util.h"
#include "dns-type.h"

typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;

/* DNS record classes, see RFC 1035 */
enum {
        DNS_CLASS_IN   = 0x01,
        DNS_CLASS_ANY  = 0xFF,
        _DNS_CLASS_MAX,
        _DNS_CLASS_INVALID = -1
};

struct DnsResourceKey {
        unsigned n_ref;
        uint16_t class, type;
        char *_name; /* don't access directy, use DNS_RESOURCE_KEY_NAME()! */
};

struct DnsResourceRecord {
        unsigned n_ref;
        DnsResourceKey *key;
        uint32_t ttl;
        bool unparseable;
        union {
                struct {
                        void *data;
                        size_t size;
                } generic;

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
                        char **strings;
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
                        bool zone_key_flag:1;
                        bool sep_flag:1;
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
DnsResourceKey* dns_resource_key_new_cname(const DnsResourceKey *key);
DnsResourceKey* dns_resource_key_new_redirect(const DnsResourceKey *key, const DnsResourceRecord *cname);
DnsResourceKey* dns_resource_key_new_consume(uint16_t class, uint16_t type, char *name);
DnsResourceKey* dns_resource_key_ref(DnsResourceKey *key);
DnsResourceKey* dns_resource_key_unref(DnsResourceKey *key);
int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b);
int dns_resource_key_match_rr(const DnsResourceKey *key, const DnsResourceRecord *rr);
int dns_resource_key_match_cname(const DnsResourceKey *key, const DnsResourceRecord *rr);
int dns_resource_key_to_string(const DnsResourceKey *key, char **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceKey*, dns_resource_key_unref);

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key);
DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name);
DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr);
DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr);
int dns_resource_record_new_reverse(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_new_address(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b);
int dns_resource_record_to_string(const DnsResourceRecord *rr, char **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceRecord*, dns_resource_record_unref);

const char *dns_class_to_string(uint16_t type);
int dns_class_from_string(const char *name, uint16_t *class);

extern const struct hash_ops dns_resource_key_hash_ops;
