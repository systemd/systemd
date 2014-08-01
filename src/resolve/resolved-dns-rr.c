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

#include "strv.h"

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

        s = strjoin(DNS_RESOURCE_KEY_NAME(key), " ", c, " ", t, NULL);
        if (!s)
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
                case DNS_TYPE_PTR:
                case DNS_TYPE_NS:
                case DNS_TYPE_CNAME:
                        free(rr->ptr.name);
                        break;
                case DNS_TYPE_HINFO:
                        free(rr->hinfo.cpu);
                        free(rr->hinfo.os);
                        break;
                case DNS_TYPE_SPF:
                case DNS_TYPE_TXT:
                        strv_free(rr->txt.strings);
                        break;
                case DNS_TYPE_SOA:
                        free(rr->soa.mname);
                        free(rr->soa.rname);
                        break;
                case DNS_TYPE_MX:
                        free(rr->mx.exchange);
                        break;
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

        switch (a->key->type) {

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
                return dns_name_equal(a->ptr.name, b->ptr.name);

        case DNS_TYPE_HINFO:
                return strcaseeq(a->hinfo.cpu, b->hinfo.cpu) &&
                       strcaseeq(a->hinfo.os, b->hinfo.os);

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT: {
                int i;

                for (i = 0; a->txt.strings[i] || b->txt.strings[i]; i++)
                        if (!streq_ptr(a->txt.strings[i], b->txt.strings[i]))
                                return false;
                return true;
        }

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

        default:
                return a->generic.size == b->generic.size &&
                        memcmp(a->generic.data, b->generic.data, a->generic.size) == 0;
        }
}

int dns_resource_record_to_string(const DnsResourceRecord *rr, char **ret) {
        _cleanup_free_ char *k = NULL;
        char *s;
        int r;

        assert(rr);

        r = dns_resource_key_to_string(rr->key, &k);
        if (r < 0)
                return r;

        switch (rr->key->type) {

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
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
        case DNS_TYPE_TXT: {
                _cleanup_free_ char *t;

                t = strv_join_quoted(rr->txt.strings);
                if (!t)
                        return -ENOMEM;

                s = strjoin(k, " ", t, NULL);
                if (!s)
                        return -ENOMEM;

                break;
        }

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

        case DNS_TYPE_AAAA: {
                _cleanup_free_ char *x = NULL;

                r = in_addr_to_string(AF_INET6, (const union in_addr_union*) &rr->aaaa.in6_addr, &x);
                if (r < 0)
                        return r;

                s = strjoin(k, " ", x, NULL);
                if (!s)
                        return -ENOMEM;
                break;
        }

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

        default: {
                _cleanup_free_ char *x = NULL;

                x = hexmem(rr->generic.data, rr->generic.size);
                if (!x)
                        return -ENOMEM;

                s = strjoin(k, " ", x, NULL);
                if (!s)
                        return -ENOMEM;
                break;
        }}

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

static const struct {
        uint16_t type;
        const char *name;
} dns_types[] = {
        { DNS_TYPE_A,     "A"     },
        { DNS_TYPE_NS,    "NS"    },
        { DNS_TYPE_CNAME, "CNAME" },
        { DNS_TYPE_SOA,   "SOA"   },
        { DNS_TYPE_PTR,   "PTR"   },
        { DNS_TYPE_HINFO, "HINFO" },
        { DNS_TYPE_MX,    "MX"    },
        { DNS_TYPE_TXT,   "TXT"   },
        { DNS_TYPE_AAAA,  "AAAA"  },
        { DNS_TYPE_SRV,   "SRV"   },
        { DNS_TYPE_SSHFP, "SSHFP" },
        { DNS_TYPE_SPF,   "SPF"   },
        { DNS_TYPE_DNAME, "DNAME" },
        { DNS_TYPE_ANY,   "ANY"   },
        { DNS_TYPE_OPT,   "OPT"   },
        { DNS_TYPE_TKEY,  "TKEY"  },
        { DNS_TYPE_TSIG,  "TSIG"  },
        { DNS_TYPE_IXFR,  "IXFR"  },
        { DNS_TYPE_AXFR,  "AXFR"  },
};


const char *dns_type_to_string(uint16_t type) {
        unsigned i;

        for (i = 0; i < ELEMENTSOF(dns_types); i++)
                if (dns_types[i].type == type)
                        return dns_types[i].name;

        return NULL;
}

int dns_type_from_string(const char *s, uint16_t *type) {
        unsigned i;

        assert(s);
        assert(type);

        for (i = 0; i < ELEMENTSOF(dns_types); i++)
                if (strcaseeq(dns_types[i].name, s)) {
                        *type = dns_types[i].type;
                        return 0;
                }

        return -EINVAL;
}
