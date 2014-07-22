/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "resolved-dns-domain.h"
#include "resolved-dns-rr.h"

DnsResourceKey* dns_resource_key_new(uint16_t class, uint16_t type, const char *name) {
        DnsResourceKey *k;
        size_t l;

        assert(name);

        l = strlen(name);
        k = malloc0(sizeof(DnsResourceKey) + l + 1);
        if (!k)
                return NULL;

        k->n_ref = 1;
        k->class = class;
        k->type = type;

        strcpy((char*) k + sizeof(DnsResourceKey), name);

        return k;
}

DnsResourceKey* dns_resource_key_new_consume(uint16_t class, uint16_t type, char *name) {
        DnsResourceKey *k;

        assert(name);

        k = new0(DnsResourceKey, 1);
        if (!k)
                return NULL;

        k->n_ref = 1;
        k->class = class;
        k->type = type;
        k->_name = name;

        return k;
}

DnsResourceKey* dns_resource_key_ref(DnsResourceKey *k) {

        if (!k)
                return NULL;

        assert(k->n_ref > 0);
        k->n_ref++;

        return k;
}

DnsResourceKey* dns_resource_key_unref(DnsResourceKey *k) {
        if (!k)
                return NULL;

        assert(k->n_ref > 0);

        if (k->n_ref == 1) {
                free(k->_name);
                free(k);
        } else
                k->n_ref--;

        return NULL;
}

int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b) {
        int r;

        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(a), DNS_RESOURCE_KEY_NAME(b));
        if (r <= 0)
                return r;

        if (a->class != b->class)
                return 0;

        if (a->type != b->type)
                return 0;

        return 1;
}

int dns_resource_key_match_rr(const DnsResourceKey *key, const DnsResourceRecord *rr) {
        assert(key);
        assert(rr);

        if (rr->key->class != key->class && key->class != DNS_CLASS_ANY)
                return 0;

        if (rr->key->type != key->type && key->type != DNS_TYPE_ANY)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), DNS_RESOURCE_KEY_NAME(key));
}

int dns_resource_key_match_cname(const DnsResourceKey *key, const DnsResourceRecord *rr) {
        assert(key);
        assert(rr);

        if (rr->key->class != key->class && key->class != DNS_CLASS_ANY)
                return 0;

        if (rr->key->type != DNS_TYPE_CNAME)
                return 0;

        return dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), DNS_RESOURCE_KEY_NAME(key));
}

unsigned long dns_resource_key_hash_func(const void *i, const uint8_t hash_key[HASH_KEY_SIZE]) {
        const DnsResourceKey *k = i;
        unsigned long ul;

        ul = dns_name_hash_func(DNS_RESOURCE_KEY_NAME(k), hash_key);
        ul = ul * hash_key[0] + ul + k->class;
        ul = ul * hash_key[1] + ul + k->type;

        return ul;
}

int dns_resource_key_compare_func(const void *a, const void *b) {
        const DnsResourceKey *x = a, *y = b;
        int ret;

        ret = dns_name_compare_func(DNS_RESOURCE_KEY_NAME(x), DNS_RESOURCE_KEY_NAME(y));
        if (ret != 0)
                return ret;

        if (x->type < y->type)
                return -1;
        if (x->type > y->type)
                return 1;

        if (x->class < y->class)
                return -1;
        if (x->class > y->class)
                return 1;

        return 0;
}

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key) {
        DnsResourceRecord *rr;

        rr = new0(DnsResourceRecord, 1);
        if (!rr)
                return NULL;

        rr->n_ref = 1;
        rr->key = dns_resource_key_ref(key);

        return rr;
}

DnsResourceRecord* dns_resource_record_ref(DnsResourceRecord *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);
        rr->n_ref++;

        return rr;
}

DnsResourceRecord* dns_resource_record_unref(DnsResourceRecord *rr) {
        if (!rr)
                return NULL;

        assert(rr->n_ref > 0);

        if (rr->n_ref > 1) {
                rr->n_ref--;
                return NULL;
        }

        if (rr->key) {
                if (IN_SET(rr->key->type, DNS_TYPE_PTR, DNS_TYPE_NS, DNS_TYPE_CNAME))
                        free(rr->ptr.name);
                else if (rr->key->type == DNS_TYPE_HINFO) {
                        free(rr->hinfo.cpu);
                        free(rr->hinfo.os);
                } else if (!IN_SET(rr->key->type, DNS_TYPE_A, DNS_TYPE_AAAA))
                        free(rr->generic.data);

                dns_resource_key_unref(rr->key);
        }

        free(rr);

        return NULL;
}

int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b) {
        int r;

        assert(a);
        assert(b);

        r = dns_resource_key_equal(a->key, b->key);
        if (r <= 0)
                return r;

        if (IN_SET(a->key->type, DNS_TYPE_PTR, DNS_TYPE_NS, DNS_TYPE_CNAME))
                return dns_name_equal(a->ptr.name, b->ptr.name);
        else if (a->key->type == DNS_TYPE_HINFO)
                return strcasecmp(a->hinfo.cpu, b->hinfo.cpu) == 0 &&
                       strcasecmp(a->hinfo.os, b->hinfo.os) == 0;
        else if (a->key->type == DNS_TYPE_A)
                return memcmp(&a->a.in_addr, &b->a.in_addr, sizeof(struct in_addr)) == 0;
        else if (a->key->type == DNS_TYPE_AAAA)
                return memcmp(&a->aaaa.in6_addr, &b->aaaa.in6_addr, sizeof(struct in6_addr)) == 0;
        else
                return a->generic.size == b->generic.size &&
                        memcmp(a->generic.data, b->generic.data, a->generic.size) == 0;
}

const char *dns_class_to_string(uint16_t class) {

        switch (class) {

        case DNS_CLASS_IN:
                return "IN";

        case DNS_CLASS_ANY:
                return "ANY";
        }

        return NULL;
}

const char *dns_type_to_string(uint16_t type) {

        switch (type) {

        case DNS_TYPE_A:
                return "A";

        case DNS_TYPE_NS:
                return "NS";

        case DNS_TYPE_CNAME:
                return "CNAME";

        case DNS_TYPE_SOA:
                return "SOA";

        case DNS_TYPE_PTR:
                return "PTR";

        case DNS_TYPE_HINFO:
                return "HINFO";

        case DNS_TYPE_MX:
                return "MX";

        case DNS_TYPE_TXT:
                return "TXT";

        case DNS_TYPE_AAAA:
                return "AAAA";

        case DNS_TYPE_SRV:
                return "SRV";

        case DNS_TYPE_SSHFP:
                return "SSHFP";

        case DNS_TYPE_DNAME:
                return "DNAME";

        case DNS_TYPE_ANY:
                return "ANY";

        case DNS_TYPE_OPT:
                return "OPT";

        case DNS_TYPE_TKEY:
                return "TKEY";

        case DNS_TYPE_TSIG:
                return "TSIG";

        case DNS_TYPE_IXFR:
                return "IXFR";

        case DNS_TYPE_AXFR:
                return "AXFR";
        }

        return NULL;
}
