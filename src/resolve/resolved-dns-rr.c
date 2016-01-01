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

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "hexdecoct.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

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

DnsResourceKey* dns_resource_key_new_redirect(const DnsResourceKey *key, const DnsResourceRecord *cname) {
        int r;

        assert(key);
        assert(cname);

        assert(IN_SET(cname->key->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME));

        if (cname->key->type == DNS_TYPE_CNAME)
                return dns_resource_key_new(key->class, key->type, cname->cname.name);
        else {
                DnsResourceKey *k;
                char *destination = NULL;

                r = dns_name_change_suffix(DNS_RESOURCE_KEY_NAME(key), DNS_RESOURCE_KEY_NAME(cname->key), cname->dname.name, &destination);
                if (r < 0)
                        return NULL;
                if (r == 0)
                        return dns_resource_key_ref((DnsResourceKey*) key);

                k = dns_resource_key_new_consume(key->class, key->type, destination);
                if (!k) {
                        free(destination);
                        return NULL;
                }

                return k;
        }
}

int dns_resource_key_new_append_suffix(DnsResourceKey **ret, DnsResourceKey *key, char *name) {
        DnsResourceKey *new_key;
        char *joined;
        int r;

        assert(ret);
        assert(key);
        assert(name);

        if (dns_name_is_root(name)) {
                *ret = dns_resource_key_ref(key);
                return 0;
        }

        r = dns_name_concat(DNS_RESOURCE_KEY_NAME(key), name, &joined);
        if (r < 0)
                return r;

        new_key = dns_resource_key_new_consume(key->class, key->type, joined);
        if (!new_key) {
                free(joined);
                return -ENOMEM;
        }

        *ret = new_key;
        return 0;
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

        /* Static/const keys created with DNS_RESOURCE_KEY_CONST will
         * set this to -1, they should not be reffed/unreffed */
        assert(k->n_ref != (unsigned) -1);

        assert(k->n_ref > 0);
        k->n_ref++;

        return k;
}

DnsResourceKey* dns_resource_key_unref(DnsResourceKey *k) {
        if (!k)
                return NULL;

        assert(k->n_ref != (unsigned) -1);
        assert(k->n_ref > 0);

        if (k->n_ref == 1) {
                free(k->_name);
                free(k);
        } else
                k->n_ref--;

        return NULL;
}

bool dns_resource_key_is_address(const DnsResourceKey *key) {
        assert(key);

        /* Check if this is an A or AAAA resource key */

        return key->class == DNS_CLASS_IN && IN_SET(key->type, DNS_TYPE_A, DNS_TYPE_AAAA);
}

int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b) {
        int r;

        if (a == b)
                return 1;

        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(a), DNS_RESOURCE_KEY_NAME(b));
        if (r <= 0)
                return r;

        if (a->class != b->class)
                return 0;

        if (a->type != b->type)
                return 0;

        return 1;
}

int dns_resource_key_match_rr(const DnsResourceKey *key, DnsResourceRecord *rr, const char *search_domain) {
        int r;

        assert(key);
        assert(rr);

        if (key == rr->key)
                return 1;

        /* Checks if an rr matches the specified key. If a search
         * domain is specified, it will also be checked if the key
         * with the search domain suffixed might match the RR. */

        if (rr->key->class != key->class && key->class != DNS_CLASS_ANY)
                return 0;

        if (rr->key->type != key->type && key->type != DNS_TYPE_ANY)
                return 0;

        r = dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), DNS_RESOURCE_KEY_NAME(key));
        if (r != 0)
                return r;

        if (search_domain) {
                _cleanup_free_ char *joined = NULL;

                r = dns_name_concat(DNS_RESOURCE_KEY_NAME(key), search_domain, &joined);
                if (r < 0)
                        return r;

                return dns_name_equal(DNS_RESOURCE_KEY_NAME(rr->key), joined);
        }

        return 0;
}

int dns_resource_key_match_cname_or_dname(const DnsResourceKey *key, const DnsResourceKey *cname, const char *search_domain) {
        int r;

        assert(key);
        assert(cname);

        if (cname->class != key->class && key->class != DNS_CLASS_ANY)
                return 0;

        if (cname->type == DNS_TYPE_CNAME)
                r = dns_name_equal(DNS_RESOURCE_KEY_NAME(key), DNS_RESOURCE_KEY_NAME(cname));
        else if (cname->type == DNS_TYPE_DNAME)
                r = dns_name_endswith(DNS_RESOURCE_KEY_NAME(key), DNS_RESOURCE_KEY_NAME(cname));
        else
                return 0;

        if (r != 0)
                return r;

        if (search_domain) {
                _cleanup_free_ char *joined = NULL;

                r = dns_name_concat(DNS_RESOURCE_KEY_NAME(key), search_domain, &joined);
                if (r < 0)
                        return r;

                if (cname->type == DNS_TYPE_CNAME)
                        return dns_name_equal(joined, DNS_RESOURCE_KEY_NAME(cname));
                else if (cname->type == DNS_TYPE_DNAME)
                        return dns_name_endswith(joined, DNS_RESOURCE_KEY_NAME(cname));
        }

        return 0;
}

int dns_resource_key_match_soa(const DnsResourceKey *key, const DnsResourceKey *soa) {
        assert(soa);
        assert(key);

        /* Checks whether 'soa' is a SOA record for the specified key. */

        if (soa->class != key->class)
                return 0;

        if (soa->type != DNS_TYPE_SOA)
                return 0;

        return dns_name_endswith(DNS_RESOURCE_KEY_NAME(key), DNS_RESOURCE_KEY_NAME(soa));
}

static void dns_resource_key_hash_func(const void *i, struct siphash *state) {
        const DnsResourceKey *k = i;

        assert(k);

        dns_name_hash_func(DNS_RESOURCE_KEY_NAME(k), state);
        siphash24_compress(&k->class, sizeof(k->class), state);
        siphash24_compress(&k->type, sizeof(k->type), state);
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
        char cbuf[strlen("CLASS") + DECIMAL_STR_MAX(uint16_t)], tbuf[strlen("TYPE") + DECIMAL_STR_MAX(uint16_t)];
        const char *c, *t;
        char *s;

        /* If we cannot convert the CLASS/TYPE into a known string,
           use the format recommended by RFC 3597, Section 5. */

        c = dns_class_to_string(key->class);
        if (!c) {
                sprintf(cbuf, "CLASS%u", key->class);
                c = cbuf;
        }

        t = dns_type_to_string(key->type);
        if (!t){
                sprintf(tbuf, "TYPE%u", key->type);
                t = tbuf;
        }

        if (asprintf(&s, "%s. %s %-5s", DNS_RESOURCE_KEY_NAME(key), c, t) < 0)
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
        rr->expiry = USEC_INFINITY;

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
                        dns_txt_item_free_all(rr->txt.items);
                        break;

                case DNS_TYPE_SOA:
                        free(rr->soa.mname);
                        free(rr->soa.rname);
                        break;

                case DNS_TYPE_MX:
                        free(rr->mx.exchange);
                        break;

                case DNS_TYPE_DS:
                        free(rr->ds.digest);
                        break;

                case DNS_TYPE_SSHFP:
                        free(rr->sshfp.fingerprint);
                        break;

                case DNS_TYPE_DNSKEY:
                        free(rr->dnskey.key);
                        break;

                case DNS_TYPE_RRSIG:
                        free(rr->rrsig.signer);
                        free(rr->rrsig.signature);
                        break;

                case DNS_TYPE_NSEC:
                        free(rr->nsec.next_domain_name);
                        bitmap_free(rr->nsec.types);
                        break;

                case DNS_TYPE_NSEC3:
                        free(rr->nsec3.next_hashed_name);
                        free(rr->nsec3.salt);
                        bitmap_free(rr->nsec3.types);
                        break;

                case DNS_TYPE_LOC:
                case DNS_TYPE_A:
                case DNS_TYPE_AAAA:
                        break;

                default:
                        free(rr->generic.data);
                }

                free(rr->wire_format);
                dns_resource_key_unref(rr->key);
        }

        free(rr->to_string);
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

int dns_resource_record_new_address(DnsResourceRecord **ret, int family, const union in_addr_union *address, const char *name) {
        DnsResourceRecord *rr;

        assert(ret);
        assert(address);
        assert(family);

        if (family == AF_INET) {

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
                if (!rr)
                        return -ENOMEM;

                rr->a.in_addr = address->in;

        } else if (family == AF_INET6) {

                rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, name);
                if (!rr)
                        return -ENOMEM;

                rr->aaaa.in6_addr = address->in6;
        } else
                return -EAFNOSUPPORT;

        *ret = rr;

        return 0;
}

int dns_resource_record_equal(const DnsResourceRecord *a, const DnsResourceRecord *b) {
        int r;

        assert(a);
        assert(b);

        if (a == b)
                return 1;

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
                return dns_txt_item_equal(a->txt.items, b->txt.items);

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

        case DNS_TYPE_DS:
                return a->ds.key_tag == b->ds.key_tag &&
                       a->ds.algorithm == b->ds.algorithm &&
                       a->ds.digest_type == b->ds.digest_type &&
                       a->ds.digest_size == b->ds.digest_size &&
                       memcmp(a->ds.digest, b->ds.digest, a->ds.digest_size) == 0;

        case DNS_TYPE_SSHFP:
                return a->sshfp.algorithm == b->sshfp.algorithm &&
                       a->sshfp.fptype == b->sshfp.fptype &&
                       a->sshfp.fingerprint_size == b->sshfp.fingerprint_size &&
                       memcmp(a->sshfp.fingerprint, b->sshfp.fingerprint, a->sshfp.fingerprint_size) == 0;

        case DNS_TYPE_DNSKEY:
                return a->dnskey.flags == b->dnskey.flags &&
                       a->dnskey.protocol == b->dnskey.protocol &&
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

        case DNS_TYPE_NSEC:
                return dns_name_equal(a->nsec.next_domain_name, b->nsec.next_domain_name) &&
                       bitmap_equal(a->nsec.types, b->nsec.types);

        case DNS_TYPE_NSEC3:
                return a->nsec3.algorithm == b->nsec3.algorithm &&
                    a->nsec3.flags == b->nsec3.flags &&
                    a->nsec3.iterations == b->nsec3.iterations &&
                    a->nsec3.salt_size == b->nsec3.salt_size &&
                    memcmp(a->nsec3.salt, b->nsec3.salt, a->nsec3.salt_size) == 0 &&
                    memcmp(a->nsec3.next_hashed_name, b->nsec3.next_hashed_name, a->nsec3.next_hashed_name_size) == 0 &&
                    bitmap_equal(a->nsec3.types, b->nsec3.types);

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

static int format_timestamp_dns(char *buf, size_t l, time_t sec) {
        struct tm tm;

        assert(buf);
        assert(l > strlen("YYYYMMDDHHmmSS"));

        if (!gmtime_r(&sec, &tm))
                return -EINVAL;

        if (strftime(buf, l, "%Y%m%d%H%M%S", &tm) <= 0)
                return -EINVAL;

        return 0;
}

static char *format_types(Bitmap *types) {
        _cleanup_strv_free_ char **strv = NULL;
        _cleanup_free_ char *str = NULL;
        Iterator i;
        unsigned type;
        int r;

        BITMAP_FOREACH(type, types, i) {
                if (dns_type_to_string(type)) {
                        r = strv_extend(&strv, dns_type_to_string(type));
                        if (r < 0)
                                return NULL;
                } else {
                        char *t;

                        r = asprintf(&t, "TYPE%u", type);
                        if (r < 0)
                                return NULL;

                        r = strv_consume(&strv, t);
                        if (r < 0)
                                return NULL;
                }
        }

        str = strv_join(strv, " ");
        if (!str)
                return NULL;

        return strjoin("( ", str, " )", NULL);
}

static char *format_txt(DnsTxtItem *first) {
        DnsTxtItem *i;
        size_t c = 1;
        char *p, *s;

        LIST_FOREACH(items, i, first)
                c += i->length * 4 + 3;

        p = s = new(char, c);
        if (!s)
                return NULL;

        LIST_FOREACH(items, i, first) {
                size_t j;

                if (i != first)
                        *(p++) = ' ';

                *(p++) = '"';

                for (j = 0; j < i->length; j++) {
                        if (i->data[j] < ' ' || i->data[j] == '"' || i->data[j] >= 127) {
                                *(p++) = '\\';
                                *(p++) = '0' + (i->data[j] / 100);
                                *(p++) = '0' + ((i->data[j] / 10) % 10);
                                *(p++) = '0' + (i->data[j] % 10);
                        } else
                                *(p++) = i->data[j];
                }

                *(p++) = '"';
        }

        *p = 0;
        return s;
}

const char *dns_resource_record_to_string(DnsResourceRecord *rr) {
        _cleanup_free_ char *k = NULL, *t = NULL;
        char *s;
        int r;

        assert(rr);

        if (rr->to_string)
                return rr->to_string;

        r = dns_resource_key_to_string(rr->key, &k);
        if (r < 0)
                return NULL;

        switch (rr->unparseable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                r = asprintf(&s, "%s %u %u %u %s",
                             k,
                             rr->srv.priority,
                             rr->srv.weight,
                             rr->srv.port,
                             strna(rr->srv.name));
                if (r < 0)
                        return NULL;
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                s = strjoin(k, " ", rr->ptr.name, NULL);
                if (!s)
                        return NULL;

                break;

        case DNS_TYPE_HINFO:
                s = strjoin(k, " ", rr->hinfo.cpu, " ", rr->hinfo.os, NULL);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                t = format_txt(rr->txt.items);
                if (!t)
                        return NULL;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_A: {
                _cleanup_free_ char *x = NULL;

                r = in_addr_to_string(AF_INET, (const union in_addr_union*) &rr->a.in_addr, &x);
                if (r < 0)
                        return NULL;

                s = strjoin(k, " ", x, NULL);
                if (!s)
                        return NULL;
                break;
        }

        case DNS_TYPE_AAAA:
                r = in_addr_to_string(AF_INET6, (const union in_addr_union*) &rr->aaaa.in6_addr, &t);
                if (r < 0)
                        return NULL;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return NULL;
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
                        return NULL;
                break;

        case DNS_TYPE_MX:
                r = asprintf(&s, "%s %u %s",
                             k,
                             rr->mx.priority,
                             rr->mx.exchange);
                if (r < 0)
                        return NULL;
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
                        return NULL;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_DS:
                t = hexmem(rr->ds.digest, rr->ds.digest_size);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %u %u %u %s",
                             k,
                             rr->ds.key_tag,
                             rr->ds.algorithm,
                             rr->ds.digest_type,
                             t);
                if (r < 0)
                        return NULL;
                break;

        case DNS_TYPE_SSHFP:
                t = hexmem(rr->sshfp.fingerprint, rr->sshfp.fingerprint_size);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %u %u %s",
                             k,
                             rr->sshfp.algorithm,
                             rr->sshfp.fptype,
                             t);
                if (r < 0)
                        return NULL;
                break;

        case DNS_TYPE_DNSKEY: {
                const char *alg;

                alg = dnssec_algorithm_to_string(rr->dnskey.algorithm);

                t = base64mem(rr->dnskey.key, rr->dnskey.key_size);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %u %u %.*s%.*u %s",
                             k,
                             rr->dnskey.flags,
                             rr->dnskey.protocol,
                             alg ? -1 : 0, alg,
                             alg ? 0 : 1, alg ? 0u : (unsigned) rr->dnskey.algorithm,
                             t);
                if (r < 0)
                        return NULL;
                break;
        }

        case DNS_TYPE_RRSIG: {
                const char *type, *alg;
                char expiration[strlen("YYYYMMDDHHmmSS") + 1], inception[strlen("YYYYMMDDHHmmSS") + 1];

                type = dns_type_to_string(rr->rrsig.type_covered);
                alg = dnssec_algorithm_to_string(rr->rrsig.algorithm);

                t = base64mem(rr->rrsig.signature, rr->rrsig.signature_size);
                if (!t)
                        return NULL;

                r = format_timestamp_dns(expiration, sizeof(expiration), rr->rrsig.expiration);
                if (r < 0)
                        return NULL;

                r = format_timestamp_dns(inception, sizeof(inception), rr->rrsig.inception);
                if (r < 0)
                        return NULL;

                /* TYPE?? follows
                 * http://tools.ietf.org/html/rfc3597#section-5 */

                r = asprintf(&s, "%s %s%.*u %.*s%.*u %u %u %s %s %u %s %s",
                             k,
                             type ?: "TYPE",
                             type ? 0 : 1, type ? 0u : (unsigned) rr->rrsig.type_covered,
                             alg ? -1 : 0, alg,
                             alg ? 0 : 1, alg ? 0u : (unsigned) rr->rrsig.algorithm,
                             rr->rrsig.labels,
                             rr->rrsig.original_ttl,
                             expiration,
                             inception,
                             rr->rrsig.key_tag,
                             rr->rrsig.signer,
                             t);
                if (r < 0)
                        return NULL;
                break;
        }

        case DNS_TYPE_NSEC:
                t = format_types(rr->nsec.types);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %s %s",
                             k,
                             rr->nsec.next_domain_name,
                             t);
                if (r < 0)
                        return NULL;
                break;

        case DNS_TYPE_NSEC3: {
                _cleanup_free_ char *salt = NULL, *hash = NULL;

                if (rr->nsec3.salt_size > 0) {
                        salt = hexmem(rr->nsec3.salt, rr->nsec3.salt_size);
                        if (!salt)
                                return NULL;
                }

                hash = base32hexmem(rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size, false);
                if (!hash)
                        return NULL;

                t = format_types(rr->nsec3.types);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %"PRIu8" %"PRIu8" %"PRIu16" %s %s %s",
                             k,
                             rr->nsec3.algorithm,
                             rr->nsec3.flags,
                             rr->nsec3.iterations,
                             rr->nsec3.salt_size > 0 ? salt : "-",
                             hash,
                             t);
                if (r < 0)
                        return NULL;

                break;
        }

        default:
                t = hexmem(rr->generic.data, rr->generic.size);
                if (!t)
                        return NULL;

                /* Format as documented in RFC 3597, Section 5 */
                r = asprintf(&s, "%s \\# %zu %s", k, rr->generic.size, t);
                if (r < 0)
                        return NULL;
                break;
        }

        rr->to_string = s;
        return s;
}

int dns_resource_record_to_wire_format(DnsResourceRecord *rr, bool canonical) {

        DnsPacket packet = {
                .n_ref = 1,
                .protocol = DNS_PROTOCOL_DNS,
                .on_stack = true,
                .refuse_compression = true,
                .canonical_form = canonical,
        };

        size_t start, rds;
        int r;

        assert(rr);

        /* Generates the RR in wire-format, optionally in the
         * canonical form as discussed in the DNSSEC RFC 4034, Section
         * 6.2. We allocate a throw-away DnsPacket object on the stack
         * here, because we need some book-keeping for memory
         * management, and can reuse the DnsPacket serializer, that
         * can generate the canonical form, too, but also knows label
         * compression and suchlike. */

        if (rr->wire_format && rr->wire_format_canonical == canonical)
                return 0;

        r = dns_packet_append_rr(&packet, rr, &start, &rds);
        if (r < 0)
                return r;

        assert(start == 0);
        assert(packet._data);

        free(rr->wire_format);
        rr->wire_format = packet._data;
        rr->wire_format_size = packet.size;
        rr->wire_format_rdata_offset = rds;
        rr->wire_format_canonical = canonical;

        packet._data = NULL;
        dns_packet_unref(&packet);

        return 0;
}

DnsTxtItem *dns_txt_item_free_all(DnsTxtItem *i) {
        DnsTxtItem *n;

        if (!i)
                return NULL;

        n = i->items_next;

        free(i);
        return dns_txt_item_free_all(n);
}

bool dns_txt_item_equal(DnsTxtItem *a, DnsTxtItem *b) {

        if (a == b)
                return true;

        if (!a != !b)
                return false;

        if (!a)
                return true;

        if (a->length != b->length)
                return false;

        if (memcmp(a->data, b->data, a->length) != 0)
                return false;

        return dns_txt_item_equal(a->items_next, b->items_next);
}

static const char* const dnssec_algorithm_table[_DNSSEC_ALGORITHM_MAX_DEFINED] = {
        /* Mnemonics as listed on https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml */
        [DNSSEC_ALGORITHM_RSAMD5]             = "RSAMD5",
        [DNSSEC_ALGORITHM_DH]                 = "DH",
        [DNSSEC_ALGORITHM_DSA]                = "DSA",
        [DNSSEC_ALGORITHM_ECC]                = "ECC",
        [DNSSEC_ALGORITHM_RSASHA1]            = "RSASHA1",
        [DNSSEC_ALGORITHM_DSA_NSEC3_SHA1]     = "DSA-NSEC3-SHA1",
        [DNSSEC_ALGORITHM_RSASHA1_NSEC3_SHA1] = "RSASHA1-NSEC3-SHA1",
        [DNSSEC_ALGORITHM_RSASHA256]          = "RSASHA256",
        [DNSSEC_ALGORITHM_RSASHA512]          = "RSASHA512",
        [DNSSEC_ALGORITHM_ECC_GOST]           = "ECC-GOST",
        [DNSSEC_ALGORITHM_ECDSAP256SHA256]    = "ECDSAP256SHA256",
        [DNSSEC_ALGORITHM_ECDSAP384SHA384]    = "ECDSAP384SHA384",
        [DNSSEC_ALGORITHM_INDIRECT]           = "INDIRECT",
        [DNSSEC_ALGORITHM_PRIVATEDNS]         = "PRIVATEDNS",
        [DNSSEC_ALGORITHM_PRIVATEOID]         = "PRIVATEOID",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_algorithm, int);

static const char* const dnssec_digest_table[_DNSSEC_DIGEST_MAX_DEFINED] = {
        /* Names as listed on https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml */
        [DNSSEC_DIGEST_SHA1] = "SHA-1",
        [DNSSEC_DIGEST_SHA256] = "SHA-256",
        [DNSSEC_DIGEST_GOST_R_34_11_94] = "GOST_R_34.11-94",
        [DNSSEC_DIGEST_SHA384] = "SHA-384",
};
DEFINE_STRING_TABLE_LOOKUP(dnssec_digest, int);
