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

#include <inttypes.h>
#include <netinet/in.h>

#include "util.h"
#include "hashmap.h"
#include "in-addr-util.h"

typedef struct DnsResourceKey DnsResourceKey;
typedef struct DnsResourceRecord DnsResourceRecord;

/* DNS record classes, see RFC 1035 */
enum {
        DNS_CLASS_IN   = 0x01,
        DNS_CLASS_ANY  = 0xFF,
        _DNS_CLASS_MAX,
        _DNS_CLASS_INVALID = -1
};

/* DNS record types, see RFC 1035 */
enum {
        /* Normal records */
        DNS_TYPE_A     = 0x01,
        DNS_TYPE_NS    = 0x02,
        DNS_TYPE_CNAME = 0x05,
        DNS_TYPE_SOA   = 0x06,
        DNS_TYPE_PTR   = 0x0C,
        DNS_TYPE_HINFO = 0x0D,
        DNS_TYPE_MX    = 0x0F,
        DNS_TYPE_TXT   = 0x10,
        DNS_TYPE_AAAA  = 0x1C,
        DNS_TYPE_SRV   = 0x21,
        DNS_TYPE_DNAME = 0x27,
        DNS_TYPE_SSHFP = 0x2C,

        DNS_TYPE_SPF   = 0x63,

        /* Special records */
        DNS_TYPE_ANY   = 0xFF,
        DNS_TYPE_OPT   = 0x29,      /* EDNS0 option */
        DNS_TYPE_TKEY  = 0xF9,
        DNS_TYPE_TSIG  = 0xFA,
        DNS_TYPE_IXFR  = 0xFB,
        DNS_TYPE_AXFR  = 0xFC,
        _DNS_TYPE_MAX,
        _DNS_TYPE_INVALID = -1
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
        union {
                struct {
                        void *data;
                        uint16_t size;
                } generic;

                /* struct { */
                /*         uint16_t priority; */
                /*         uint16_t weight; */
                /*         uint16_t port; */
                /*         char *name; */
                /* } srv; */

                struct {
                        char *name;
                } ptr, ns, cname;

                struct {
                        char *cpu;
                        char *os;
                } hinfo;

                struct {
                        char **strings;
                } txt;

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
DnsResourceKey* dns_resource_key_new_consume(uint16_t class, uint16_t type, char *name);
DnsResourceKey* dns_resource_key_ref(DnsResourceKey *key);
DnsResourceKey* dns_resource_key_unref(DnsResourceKey *key);
int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b);
int dns_resource_key_match_rr(const DnsResourceKey *key, const DnsResourceRecord *rr);
int dns_resource_key_match_cname(const DnsResourceKey *key, const DnsResourceRecord *rr);
unsigned long dns_resource_key_hash_func(const void *i, const uint8_t hash_key[HASH_KEY_SIZE]);
int dns_resource_key_compare_func(const void *a, const void *b);
int dns_resource_key_to_string(const DnsResourceKey *key, char **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceKey*, dns_resource_key_unref);

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key);
DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name);
DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr);
DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr);
int dns_resource_record_new_reverse(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name);
int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b);
int dns_resource_record_to_string(const DnsResourceRecord *rr, char **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsResourceRecord*, dns_resource_record_unref);

const char *dns_type_to_string(uint16_t type);
int dns_type_from_string(const char *name, uint16_t *type);

const char *dns_class_to_string(uint16_t type);
int dns_class_from_string(const char *name, uint16_t *class);
