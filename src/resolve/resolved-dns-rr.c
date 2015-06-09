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

#include <math.h>

#include "strv.h"

#include "dns-domain.h"
#include "resolved-dns-rr.h"
#include "resolved-dns-packet.h"
#include "dns-type.h"

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

static unsigned long dns_resource_key_hash_func(const void *i, const uint8_t hash_key[HASH_KEY_SIZE]) {
        const DnsResourceKey *k = i;
        unsigned long ul;

        ul = dns_name_hash_func(DNS_RESOURCE_KEY_NAME(k), hash_key);
        ul = ul * hash_key[0] + ul + k->class;
        ul = ul * hash_key[1] + ul + k->type;

        return ul;
}

static int dns_resource_key_compare_func(const void *a, const void *b) {
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

const struct hash_ops dns_resource_key_hash_ops = {
        .hash = dns_resource_key_hash_func,
        .compare = dns_resource_key_compare_func
};

int dns_resource_key_to_string(const DnsResourceKey *key, char **ret) {
        char cbuf[DECIMAL_STR_MAX(uint16_t)], tbuf[DECIMAL_STR_MAX(uint16_t)];
        const char *c, *t;
        char *s;

        c = dns_class_to_string(key->class);
        if (!c) {
                sprintf(cbuf, "%i", key->class);
                c = cbuf;
        }

        t = dns_type_to_string(key->type);
        if (!t){
                sprintf(tbuf, "%i", key->type);
                t = tbuf;
        }

        if (asprintf(&s, "%s %s %-5s", DNS_RESOURCE_KEY_NAME(key), c, t) < 0)
                return -ENOMEM;

        *ret = s;
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

DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        key = dns_resource_key_new(class, type, name);
        if (!key)
                return NULL;

        return dns_resource_record_new(key);
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
                switch(rr->key->type) {

                case DNS_TYPE_SRV:
                        free(rr->srv.name);
                        break;

                case DNS_TYPE_PTR:
                case DNS_TYPE_NS:
                case DNS_TYPE_CNAME:
                case DNS_TYPE_DNAME:
                        free(rr->ptr.name);
                        break;

                case DNS_TYPE_HINFO:
                        free(rr->hinfo.cpu);
                        free(rr->hinfo.os);
                        break;

                case DNS_TYPE_TXT:
                case DNS_TYPE_SPF:
                        strv_free(rr->txt.strings);
                        break;

                case DNS_TYPE_SOA:
                        free(rr->soa.mname);
                        free(rr->soa.rname);
                        break;

                case DNS_TYPE_MX:
                        free(rr->mx.exchange);
                        break;

                case DNS_TYPE_SSHFP:
                        free(rr->sshfp.key);
                        break;

                case DNS_TYPE_DNSKEY:
                        free(rr->dnskey.key);
                        break;

                case DNS_TYPE_RRSIG:
                        free(rr->rrsig.signer);
                        free(rr->rrsig.signature);
                        break;

                case DNS_TYPE_LOC:
                case DNS_TYPE_A:
                case DNS_TYPE_AAAA:
                        break;

                default:
                        free(rr->generic.data);
                }

                dns_resource_key_unref(rr->key);
        }

        free(rr);

        return NULL;
}

int dns_resource_record_new_reverse(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *hostname) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_free_ char *ptr = NULL;
        int r;

        assert(ret);
        assert(address);
        assert(hostname);

        r = dns_name_reverse(family, address, &ptr);
        if (r < 0)
                return r;

        key = dns_resource_key_new_consume(DNS_CLASS_IN, DNS_TYPE_PTR, ptr);
        if (!key)
                return -ENOMEM;

        ptr = NULL;

        rr = dns_resource_record_new(key);
        if (!rr)
                return -ENOMEM;

        rr->ptr.name = strdup(hostname);
        if (!rr->ptr.name)
                return -ENOMEM;

        *ret = rr;
        rr = NULL;

        return 0;
}

int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b) {
        int r;

        assert(a);
        assert(b);

        r = dns_resource_key_equal(a->key, b->key);
        if (r <= 0)
                return r;

        if (a->unparseable != b->unparseable)
                return 0;

        switch (a->unparseable ? _DNS_TYPE_INVALID : a->key->type) {

        case DNS_TYPE_SRV:
                r = dns_name_equal(a->srv.name, b->srv.name);
                if (r <= 0)
                        return r;

                return a->srv.priority == b->srv.priority &&
                       a->srv.weight == b->srv.weight &&
                       a->srv.port == b->srv.port;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                return dns_name_equal(a->ptr.name, b->ptr.name);

        case DNS_TYPE_HINFO:
                return strcaseeq(a->hinfo.cpu, b->hinfo.cpu) &&
                       strcaseeq(a->hinfo.os, b->hinfo.os);

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                return strv_equal(a->txt.strings, b->txt.strings);

        case DNS_TYPE_A:
                return memcmp(&a->a.in_addr, &b->a.in_addr, sizeof(struct in_addr)) == 0;

        case DNS_TYPE_AAAA:
                return memcmp(&a->aaaa.in6_addr, &b->aaaa.in6_addr, sizeof(struct in6_addr)) == 0;

        case DNS_TYPE_SOA:
                r = dns_name_equal(a->soa.mname, b->soa.mname);
                if (r <= 0)
                        return r;
                r = dns_name_equal(a->soa.rname, b->soa.rname);
                if (r <= 0)
                        return r;

                return a->soa.serial  == b->soa.serial &&
                       a->soa.refresh == b->soa.refresh &&
                       a->soa.retry   == b->soa.retry &&
                       a->soa.expire  == b->soa.expire &&
                       a->soa.minimum == b->soa.minimum;

        case DNS_TYPE_MX:
                if (a->mx.priority != b->mx.priority)
                        return 0;

                return dns_name_equal(a->mx.exchange, b->mx.exchange);

        case DNS_TYPE_LOC:
                assert(a->loc.version == b->loc.version);

                return a->loc.size == b->loc.size &&
                       a->loc.horiz_pre == b->loc.horiz_pre &&
                       a->loc.vert_pre == b->loc.vert_pre &&
                       a->loc.latitude == b->loc.latitude &&
                       a->loc.longitude == b->loc.longitude &&
                       a->loc.altitude == b->loc.altitude;

        case DNS_TYPE_SSHFP:
                return a->sshfp.algorithm == b->sshfp.algorithm &&
                       a->sshfp.fptype == b->sshfp.fptype &&
                       a->sshfp.key_size == b->sshfp.key_size &&
                       memcmp(a->sshfp.key, b->sshfp.key, a->sshfp.key_size) == 0;

        case DNS_TYPE_DNSKEY:
                return a->dnskey.zone_key_flag == b->dnskey.zone_key_flag &&
                       a->dnskey.sep_flag == b->dnskey.sep_flag &&
                       a->dnskey.algorithm == b->dnskey.algorithm &&
                       a->dnskey.key_size == b->dnskey.key_size &&
                       memcmp(a->dnskey.key, b->dnskey.key, a->dnskey.key_size) == 0;

        case DNS_TYPE_RRSIG:
                /* do the fast comparisons first */
                if (a->rrsig.type_covered != b->rrsig.type_covered ||
                    a->rrsig.algorithm != b->rrsig.algorithm ||
                    a->rrsig.labels != b->rrsig.labels ||
                    a->rrsig.original_ttl != b->rrsig.original_ttl ||
                    a->rrsig.expiration != b->rrsig.expiration ||
                    a->rrsig.inception != b->rrsig.inception ||
                    a->rrsig.key_tag != b->rrsig.key_tag ||
                    a->rrsig.signature_size != b->rrsig.signature_size ||
                    memcmp(a->rrsig.signature, b->rrsig.signature, a->rrsig.signature_size) != 0)
                        return false;

                return dns_name_equal(a->rrsig.signer, b->rrsig.signer);

        default:
                return a->generic.size == b->generic.size &&
                        memcmp(a->generic.data, b->generic.data, a->generic.size) == 0;
        }
}

static char* format_location(uint32_t latitude, uint32_t longitude, uint32_t altitude,
                             uint8_t size, uint8_t horiz_pre, uint8_t vert_pre) {
        char *s;
        char NS = latitude >= 1U<<31 ? 'N' : 'S';
        char EW = longitude >= 1U<<31 ? 'E' : 'W';

        int lat = latitude >= 1U<<31 ? (int) (latitude - (1U<<31)) : (int) ((1U<<31) - latitude);
        int lon = longitude >= 1U<<31 ? (int) (longitude - (1U<<31)) : (int) ((1U<<31) - longitude);
        double alt = altitude >= 10000000u ? altitude - 10000000u : -(double)(10000000u - altitude);
        double siz = (size >> 4) * exp10((double) (size & 0xF));
        double hor = (horiz_pre >> 4) * exp10((double) (horiz_pre & 0xF));
        double ver = (vert_pre >> 4) * exp10((double) (vert_pre & 0xF));

        if (asprintf(&s, "%d %d %.3f %c %d %d %.3f %c %.2fm %.2fm %.2fm %.2fm",
                     (lat / 60000 / 60),
                     (lat / 60000) % 60,
                     (lat % 60000) / 1000.,
                     NS,
                     (lon / 60000 / 60),
                     (lon / 60000) % 60,
                     (lon % 60000) / 1000.,
                     EW,
                     alt / 100.,
                     siz / 100.,
                     hor / 100.,
                     ver / 100.) < 0)
                return NULL;

        return s;
}

int dns_resource_record_to_string(const DnsResourceRecord *rr, char **ret) {
        _cleanup_free_ char *k = NULL, *t = NULL;
        char *s;
        int r;

        assert(rr);

        r = dns_resource_key_to_string(rr->key, &k);
        if (r < 0)
                return r;

        switch (rr->unparseable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                r = asprintf(&s, "%s %u %u %u %s",
                             k,
                             rr->srv.priority,
                             rr->srv.weight,
                             rr->srv.port,
                             strna(rr->srv.name));
                if (r < 0)
                        return -ENOMEM;
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                s = strjoin(k, " ", rr->ptr.name, NULL);
                if (!s)
                        return -ENOMEM;

                break;

        case DNS_TYPE_HINFO:
                s = strjoin(k, " ", rr->hinfo.cpu, " ", rr->hinfo.os, NULL);
                if (!s)
                        return -ENOMEM;
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                t = strv_join_quoted(rr->txt.strings);
                if (!t)
                        return -ENOMEM;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return -ENOMEM;

                break;

        case DNS_TYPE_A: {
                _cleanup_free_ char *x = NULL;

                r = in_addr_to_string(AF_INET, (const union in_addr_union*) &rr->a.in_addr, &x);
                if (r < 0)
                        return r;

                s = strjoin(k, " ", x, NULL);
                if (!s)
                        return -ENOMEM;
                break;
        }

        case DNS_TYPE_AAAA:
                r = in_addr_to_string(AF_INET6, (const union in_addr_union*) &rr->aaaa.in6_addr, &t);
                if (r < 0)
                        return r;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return -ENOMEM;
                break;

        case DNS_TYPE_SOA:
                r = asprintf(&s, "%s %s %s %u %u %u %u %u",
                             k,
                             strna(rr->soa.mname),
                             strna(rr->soa.rname),
                             rr->soa.serial,
                             rr->soa.refresh,
                             rr->soa.retry,
                             rr->soa.expire,
                             rr->soa.minimum);
                if (r < 0)
                        return -ENOMEM;
                break;

        case DNS_TYPE_MX:
                r = asprintf(&s, "%s %u %s",
                             k,
                             rr->mx.priority,
                             rr->mx.exchange);
                if (r < 0)
                        return -ENOMEM;
                break;

        case DNS_TYPE_LOC:
                assert(rr->loc.version == 0);

                t = format_location(rr->loc.latitude,
                                    rr->loc.longitude,
                                    rr->loc.altitude,
                                    rr->loc.size,
                                    rr->loc.horiz_pre,
                                    rr->loc.vert_pre);
                if (!t)
                        return -ENOMEM;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return -ENOMEM;
                break;

        case DNS_TYPE_SSHFP:
                t = hexmem(rr->sshfp.key, rr->sshfp.key_size);
                if (!t)
                        return -ENOMEM;

                r = asprintf(&s, "%s %u %u %s",
                             k,
                             rr->sshfp.algorithm,
                             rr->sshfp.fptype,
                             t);
                if (r < 0)
                        return -ENOMEM;
                break;

        case DNS_TYPE_DNSKEY: {
                const char *alg;

                alg = dnssec_algorithm_to_string(rr->dnskey.algorithm);

                t = hexmem(rr->dnskey.key, rr->dnskey.key_size);
                if (!t)
                        return -ENOMEM;

                r = asprintf(&s, "%s %u 3 %.*s%.*u %s",
                             k,
                             dnskey_to_flags(rr),
                             alg ? -1 : 0, alg,
                             alg ? 0 : 1, alg ? 0u : (unsigned) rr->dnskey.algorithm,
                             t);
                if (r < 0)
                        return -ENOMEM;
                break;
        }

        case DNS_TYPE_RRSIG: {
                const char *type, *alg;

                type = dns_type_to_string(rr->rrsig.type_covered);
                alg = dnssec_algorithm_to_string(rr->rrsig.algorithm);

                t = hexmem(rr->rrsig.signature, rr->rrsig.signature_size);
                if (!t)
                        return -ENOMEM;

                /* TYPE?? follows
                 * http://tools.ietf.org/html/rfc3597#section-5 */

                r = asprintf(&s, "%s %s%.*u %.*s%.*u %u %u %u %u %u %s %s",
                             k,
                             type ?: "TYPE",
                             type ? 0 : 1, type ? 0u : (unsigned) rr->rrsig.type_covered,
                             alg ? -1 : 0, alg,
                             alg ? 0 : 1, alg ? 0u : (unsigned) rr->rrsig.algorithm,
                             rr->rrsig.labels,
                             rr->rrsig.original_ttl,
                             rr->rrsig.expiration,
                             rr->rrsig.inception,
                             rr->rrsig.key_tag,
                             rr->rrsig.signer,
                             t);
                if (r < 0)
                        return -ENOMEM;
                break;
        }

        default:
                t = hexmem(rr->generic.data, rr->generic.size);
                if (!t)
                        return -ENOMEM;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return -ENOMEM;
                break;
        }

        *ret = s;
        return 0;
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

int dns_class_from_string(const char *s, uint16_t *class) {
        assert(s);
        assert(class);

        if (strcaseeq(s, "IN"))
                *class = DNS_CLASS_IN;
        else if (strcaseeq(s, "ANY"))
                *class = DNS_TYPE_ANY;
        else
                return -EINVAL;

        return 0;
}
