/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <math.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "escape.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "resolved-dns-dnssec.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

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
                _cleanup_free_ char *destination = NULL;
                DnsResourceKey *k;

                r = dns_name_change_suffix(dns_resource_key_name(key), dns_resource_key_name(cname->key), cname->dname.name, &destination);
                if (r < 0)
                        return NULL;
                if (r == 0)
                        return dns_resource_key_ref((DnsResourceKey*) key);

                k = dns_resource_key_new_consume(key->class, key->type, destination);
                if (!k)
                        return NULL;

                TAKE_PTR(destination);
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

        r = dns_name_concat(dns_resource_key_name(key), name, 0, &joined);
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

        k = new(DnsResourceKey, 1);
        if (!k)
                return NULL;

        *k = (DnsResourceKey) {
                .n_ref = 1,
                .class = class,
                .type = type,
                ._name = name,
        };

        return k;
}

DnsResourceKey* dns_resource_key_ref(DnsResourceKey *k) {

        if (!k)
                return NULL;

        /* Static/const keys created with DNS_RESOURCE_KEY_CONST will
         * set this to -1, they should not be reffed/unreffed */
        assert(k->n_ref != UINT_MAX);

        assert(k->n_ref > 0);
        k->n_ref++;

        return k;
}

DnsResourceKey* dns_resource_key_unref(DnsResourceKey *k) {
        if (!k)
                return NULL;

        assert(k->n_ref != UINT_MAX);
        assert(k->n_ref > 0);

        if (k->n_ref == 1) {
                free(k->_name);
                free(k);
        } else
                k->n_ref--;

        return NULL;
}

const char* dns_resource_key_name(const DnsResourceKey *key) {
        const char *name;

        if (!key)
                return NULL;

        if (key->_name)
                name = key->_name;
        else
                name = (char*) key + sizeof(DnsResourceKey);

        if (dns_name_is_root(name))
                return ".";
        else
                return name;
}

bool dns_resource_key_is_address(const DnsResourceKey *key) {
        assert(key);

        /* Check if this is an A or AAAA resource key */

        return key->class == DNS_CLASS_IN && IN_SET(key->type, DNS_TYPE_A, DNS_TYPE_AAAA);
}

bool dns_resource_key_is_dnssd_ptr(const DnsResourceKey *key) {
        assert(key);

        /* Check if this is a PTR resource key used in
           Service Instance Enumeration as described in RFC6763 p4.1. */

        if (key->type != DNS_TYPE_PTR)
                return false;

        return dns_name_endswith(dns_resource_key_name(key), "_tcp.local") ||
                dns_name_endswith(dns_resource_key_name(key), "_udp.local");
}

int dns_resource_key_equal(const DnsResourceKey *a, const DnsResourceKey *b) {
        int r;

        if (a == b)
                return 1;

        r = dns_name_equal(dns_resource_key_name(a), dns_resource_key_name(b));
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

        r = dns_name_equal(dns_resource_key_name(rr->key), dns_resource_key_name(key));
        if (r != 0)
                return r;

        if (search_domain) {
                _cleanup_free_ char *joined = NULL;

                r = dns_name_concat(dns_resource_key_name(key), search_domain, 0, &joined);
                if (r < 0)
                        return r;

                return dns_name_equal(dns_resource_key_name(rr->key), joined);
        }

        return 0;
}

int dns_resource_key_match_cname_or_dname(const DnsResourceKey *key, const DnsResourceKey *cname, const char *search_domain) {
        int r;

        assert(key);
        assert(cname);

        if (cname->class != key->class && key->class != DNS_CLASS_ANY)
                return 0;

        if (!dns_type_may_redirect(key->type))
                return 0;

        if (cname->type == DNS_TYPE_CNAME)
                r = dns_name_equal(dns_resource_key_name(key), dns_resource_key_name(cname));
        else if (cname->type == DNS_TYPE_DNAME)
                r = dns_name_endswith(dns_resource_key_name(key), dns_resource_key_name(cname));
        else
                return 0;

        if (r != 0)
                return r;

        if (search_domain) {
                _cleanup_free_ char *joined = NULL;

                r = dns_name_concat(dns_resource_key_name(key), search_domain, 0, &joined);
                if (r < 0)
                        return r;

                if (cname->type == DNS_TYPE_CNAME)
                        return dns_name_equal(joined, dns_resource_key_name(cname));
                else if (cname->type == DNS_TYPE_DNAME)
                        return dns_name_endswith(joined, dns_resource_key_name(cname));
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

        return dns_name_endswith(dns_resource_key_name(key), dns_resource_key_name(soa));
}

static void dns_resource_key_hash_func(const DnsResourceKey *k, struct siphash *state) {
        assert(k);

        dns_name_hash_func(dns_resource_key_name(k), state);
        siphash24_compress_typesafe(k->class, state);
        siphash24_compress_typesafe(k->type, state);
}

static int dns_resource_key_compare_func(const DnsResourceKey *x, const DnsResourceKey *y) {
        int r;

        r = dns_name_compare_func(dns_resource_key_name(x), dns_resource_key_name(y));
        if (r != 0)
                return r;

        r = CMP(x->type, y->type);
        if (r != 0)
                return r;

        return CMP(x->class, y->class);
}

DEFINE_HASH_OPS(dns_resource_key_hash_ops, DnsResourceKey, dns_resource_key_hash_func, dns_resource_key_compare_func);

char* dns_resource_key_to_string(const DnsResourceKey *key, char *buf, size_t buf_size) {
        const char *c, *t;
        char *ans = buf;

        /* If we cannot convert the CLASS/TYPE into a known string,
           use the format recommended by RFC 3597, Section 5. */

        c = dns_class_to_string(key->class);
        t = dns_type_to_string(key->type);

        (void) snprintf(buf, buf_size, "%s %s%s%.0u %s%s%.0u",
                        dns_resource_key_name(key),
                        strempty(c), c ? "" : "CLASS", c ? 0u : key->class,
                        strempty(t), t ? "" : "TYPE", t ? 0u : key->type);

        return ans;
}

bool dns_resource_key_reduce(DnsResourceKey **a, DnsResourceKey **b) {
        assert(a);
        assert(b);

        /* Try to replace one RR key by another if they are identical, thus saving a bit of memory. Note that we do
         * this only for RR keys, not for RRs themselves, as they carry a lot of additional metadata (where they come
         * from, validity data, and suchlike), and cannot be replaced so easily by other RRs that have the same
         * superficial data. */

        if (!*a)
                return false;
        if (!*b)
                return false;

        /* We refuse merging const keys */
        if ((*a)->n_ref == UINT_MAX)
                return false;
        if ((*b)->n_ref == UINT_MAX)
                return false;

        /* Already the same? */
        if (*a == *b)
                return true;

        /* Are they really identical? */
        if (dns_resource_key_equal(*a, *b) <= 0)
                return false;

        /* Keep the one which already has more references. */
        if ((*a)->n_ref > (*b)->n_ref)
                DNS_RESOURCE_KEY_REPLACE(*b, dns_resource_key_ref(*a));
        else
                DNS_RESOURCE_KEY_REPLACE(*a, dns_resource_key_ref(*b));

        return true;
}

DnsResourceRecord* dns_resource_record_new(DnsResourceKey *key) {
        DnsResourceRecord *rr;

        rr = new(DnsResourceRecord, 1);
        if (!rr)
                return NULL;

        *rr = (DnsResourceRecord) {
                .n_ref = 1,
                .key = dns_resource_key_ref(key),
                .expiry = USEC_INFINITY,
                .n_skip_labels_signer = UINT8_MAX,
                .n_skip_labels_source = UINT8_MAX,
        };

        return rr;
}

DnsResourceRecord* dns_resource_record_new_full(uint16_t class, uint16_t type, const char *name) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        key = dns_resource_key_new(class, type, name);
        if (!key)
                return NULL;

        return dns_resource_record_new(key);
}

static DnsResourceRecord* dns_resource_record_free(DnsResourceRecord *rr) {
        assert(rr);

        if (rr->key) {
                switch (rr->key->type) {

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

                case DNS_TYPE_TLSA:
                        free(rr->tlsa.data);
                        break;

                case DNS_TYPE_SVCB:
                case DNS_TYPE_HTTPS:
                        free(rr->svcb.target_name);
                        dns_svc_param_free_all(rr->svcb.params);
                        break;

                case DNS_TYPE_CAA:
                        free(rr->caa.tag);
                        free(rr->caa.value);
                        break;

                case DNS_TYPE_OPENPGPKEY:
                default:
                        if (!rr->unparsable)
                                free(rr->generic.data);
                }

                if (rr->unparsable)
                        free(rr->generic.data);

                free(rr->wire_format);
                dns_resource_key_unref(rr->key);
        }

        free(rr->to_string);
        return mfree(rr);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsResourceRecord, dns_resource_record, dns_resource_record_free);

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

        *ret = TAKE_PTR(rr);

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

#define FIELD_EQUAL(a, b, field) \
        ((a).field ## _size == (b).field ## _size &&  \
         memcmp_safe((a).field, (b).field, (a).field ## _size) == 0)

int dns_resource_record_payload_equal(const DnsResourceRecord *a, const DnsResourceRecord *b) {
        int r;

        /* Check if a and b are the same, but don't look at their keys */

        if (a->unparsable != b->unparsable)
                return 0;

        switch (a->unparsable ? _DNS_TYPE_INVALID : a->key->type) {

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
                       FIELD_EQUAL(a->ds, b->ds, digest);

        case DNS_TYPE_SSHFP:
                return a->sshfp.algorithm == b->sshfp.algorithm &&
                       a->sshfp.fptype == b->sshfp.fptype &&
                       FIELD_EQUAL(a->sshfp, b->sshfp, fingerprint);

        case DNS_TYPE_DNSKEY:
                return a->dnskey.flags == b->dnskey.flags &&
                       a->dnskey.protocol == b->dnskey.protocol &&
                       a->dnskey.algorithm == b->dnskey.algorithm &&
                       FIELD_EQUAL(a->dnskey, b->dnskey, key);

        case DNS_TYPE_RRSIG:
                /* do the fast comparisons first */
                return a->rrsig.type_covered == b->rrsig.type_covered &&
                       a->rrsig.algorithm == b->rrsig.algorithm &&
                       a->rrsig.labels == b->rrsig.labels &&
                       a->rrsig.original_ttl == b->rrsig.original_ttl &&
                       a->rrsig.expiration == b->rrsig.expiration &&
                       a->rrsig.inception == b->rrsig.inception &&
                       a->rrsig.key_tag == b->rrsig.key_tag &&
                       FIELD_EQUAL(a->rrsig, b->rrsig, signature) &&
                       dns_name_equal(a->rrsig.signer, b->rrsig.signer);

        case DNS_TYPE_NSEC:
                return dns_name_equal(a->nsec.next_domain_name, b->nsec.next_domain_name) &&
                       bitmap_equal(a->nsec.types, b->nsec.types);

        case DNS_TYPE_NSEC3:
                return a->nsec3.algorithm == b->nsec3.algorithm &&
                       a->nsec3.flags == b->nsec3.flags &&
                       a->nsec3.iterations == b->nsec3.iterations &&
                       FIELD_EQUAL(a->nsec3, b->nsec3, salt) &&
                       FIELD_EQUAL(a->nsec3, b->nsec3, next_hashed_name) &&
                       bitmap_equal(a->nsec3.types, b->nsec3.types);

        case DNS_TYPE_TLSA:
                return a->tlsa.cert_usage == b->tlsa.cert_usage &&
                       a->tlsa.selector == b->tlsa.selector &&
                       a->tlsa.matching_type == b->tlsa.matching_type &&
                       FIELD_EQUAL(a->tlsa, b->tlsa, data);

        case DNS_TYPE_SVCB:
        case DNS_TYPE_HTTPS:
                return a->svcb.priority == b->svcb.priority &&
                       dns_name_equal(a->svcb.target_name, b->svcb.target_name) &&
                       dns_svc_params_equal(a->svcb.params, b->svcb.params);

        case DNS_TYPE_CAA:
                return a->caa.flags == b->caa.flags &&
                       streq(a->caa.tag, b->caa.tag) &&
                       FIELD_EQUAL(a->caa, b->caa, value);

        case DNS_TYPE_OPENPGPKEY:
        default:
                return FIELD_EQUAL(a->generic, b->generic, data);
        }
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

        return dns_resource_record_payload_equal(a, b);
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
        assert(l > STRLEN("YYYYMMDDHHmmSS"));

        if (!gmtime_r(&sec, &tm))
                return -EINVAL;

        if (strftime(buf, l, "%Y%m%d%H%M%S", &tm) <= 0)
                return -EINVAL;

        return 0;
}

static char *format_types(Bitmap *types) {
        _cleanup_strv_free_ char **strv = NULL;
        _cleanup_free_ char *str = NULL;
        unsigned type;
        int r;

        BITMAP_FOREACH(type, types) {
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

        return strjoin("( ", str, " )");
}

static char *format_txt(DnsTxtItem *first) {
        size_t c = 1;
        char *p, *s;

        LIST_FOREACH(items, i, first)
                c += i->length * 4 + 3;

        p = s = new(char, c);
        if (!s)
                return NULL;

        LIST_FOREACH(items, i, first) {
                if (i != first)
                        *(p++) = ' ';

                *(p++) = '"';

                for (size_t j = 0; j < i->length; j++) {
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
        _cleanup_free_ char *s = NULL, *t = NULL;
        char k[DNS_RESOURCE_KEY_STRING_MAX];
        int r;

        assert(rr);

        if (rr->to_string)
                return rr->to_string;

        dns_resource_key_to_string(rr->key, k, sizeof(k));

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {

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
                s = strjoin(k, " ", rr->ptr.name);
                if (!s)
                        return NULL;

                break;

        case DNS_TYPE_HINFO:
                s = strjoin(k, " ", rr->hinfo.cpu, " ", rr->hinfo.os);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_SPF: /* exactly the same as TXT */
        case DNS_TYPE_TXT:
                t = format_txt(rr->txt.items);
                if (!t)
                        return NULL;

                s = strjoin(k, " ", t);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_A:
                r = in_addr_to_string(AF_INET, (const union in_addr_union*) &rr->a.in_addr, &t);
                if (r < 0)
                        return NULL;

                s = strjoin(k, " ", t);
                if (!s)
                        return NULL;
                break;

        case DNS_TYPE_AAAA:
                r = in_addr_to_string(AF_INET6, (const union in_addr_union*) &rr->aaaa.in6_addr, &t);
                if (r < 0)
                        return NULL;

                s = strjoin(k, " ", t);
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

                s = strjoin(k, " ", t);
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
                _cleanup_free_ char *alg = NULL;
                uint16_t key_tag;

                key_tag = dnssec_keytag(rr, true);

                r = dnssec_algorithm_to_string_alloc(rr->dnskey.algorithm, &alg);
                if (r < 0)
                        return NULL;

                r = asprintf(&t, "%s %u %u %s",
                             k,
                             rr->dnskey.flags,
                             rr->dnskey.protocol,
                             alg);
                if (r < 0)
                        return NULL;

                r = base64_append(&t, r,
                                  rr->dnskey.key, rr->dnskey.key_size,
                                  8, columns());
                if (r < 0)
                        return NULL;

                r = asprintf(&s, "%s\n"
                             "        -- Flags:%s%s%s\n"
                             "        -- Key tag: %u",
                             t,
                             rr->dnskey.flags & DNSKEY_FLAG_SEP ? " SEP" : "",
                             rr->dnskey.flags & DNSKEY_FLAG_REVOKE ? " REVOKE" : "",
                             rr->dnskey.flags & DNSKEY_FLAG_ZONE_KEY ? " ZONE_KEY" : "",
                             key_tag);
                if (r < 0)
                        return NULL;

                break;
        }

        case DNS_TYPE_RRSIG: {
                _cleanup_free_ char *alg = NULL;
                char expiration[STRLEN("YYYYMMDDHHmmSS") + 1], inception[STRLEN("YYYYMMDDHHmmSS") + 1];
                const char *type;

                type = dns_type_to_string(rr->rrsig.type_covered);

                r = dnssec_algorithm_to_string_alloc(rr->rrsig.algorithm, &alg);
                if (r < 0)
                        return NULL;

                r = format_timestamp_dns(expiration, sizeof(expiration), rr->rrsig.expiration);
                if (r < 0)
                        return NULL;

                r = format_timestamp_dns(inception, sizeof(inception), rr->rrsig.inception);
                if (r < 0)
                        return NULL;

                /* TYPE?? follows
                 * http://tools.ietf.org/html/rfc3597#section-5 */

                r = asprintf(&s, "%s %s%.*u %s %u %u %s %s %u %s",
                             k,
                             type ?: "TYPE",
                             type ? 0 : 1, type ? 0u : (unsigned) rr->rrsig.type_covered,
                             alg,
                             rr->rrsig.labels,
                             rr->rrsig.original_ttl,
                             expiration,
                             inception,
                             rr->rrsig.key_tag,
                             rr->rrsig.signer);
                if (r < 0)
                        return NULL;

                r = base64_append(&s, r,
                                  rr->rrsig.signature, rr->rrsig.signature_size,
                                  8, columns());
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

        case DNS_TYPE_TLSA:
                t = hexmem(rr->tlsa.data, rr->tlsa.data_size);
                if (!t)
                        return NULL;

                r = asprintf(&s,
                             "%s %u %u %u %s\n"
                             "        -- Cert. usage: %s\n"
                             "        -- Selector: %s\n"
                             "        -- Matching type: %s",
                             k,
                             rr->tlsa.cert_usage,
                             rr->tlsa.selector,
                             rr->tlsa.matching_type,
                             t,
                             tlsa_cert_usage_to_string(rr->tlsa.cert_usage),
                             tlsa_selector_to_string(rr->tlsa.selector),
                             tlsa_matching_type_to_string(rr->tlsa.matching_type));
                if (r < 0)
                        return NULL;

                break;

        case DNS_TYPE_CAA:
                t = octescape(rr->caa.value, rr->caa.value_size);
                if (!t)
                        return NULL;

                r = asprintf(&s, "%s %u %s \"%s\"%s%s%s%.0u",
                             k,
                             rr->caa.flags,
                             rr->caa.tag,
                             t,
                             rr->caa.flags ? "\n        -- Flags:" : "",
                             rr->caa.flags & CAA_FLAG_CRITICAL ? " critical" : "",
                             rr->caa.flags & ~CAA_FLAG_CRITICAL ? " " : "",
                             rr->caa.flags & ~CAA_FLAG_CRITICAL);
                if (r < 0)
                        return NULL;

                break;

        case DNS_TYPE_OPENPGPKEY:
                r = asprintf(&s, "%s", k);
                if (r < 0)
                        return NULL;

                r = base64_append(&s, r,
                                  rr->generic.data, rr->generic.data_size,
                                  8, columns());
                if (r < 0)
                        return NULL;
                break;

        default:
                /* Format as documented in RFC 3597, Section 5 */
                if (rr->generic.data_size == 0)
                        r = asprintf(&s, "%s \\# 0", k);
                else {
                        t = hexmem(rr->generic.data, rr->generic.data_size);
                        if (!t)
                                return NULL;
                        r = asprintf(&s, "%s \\# %zu %s", k, rr->generic.data_size, t);
                }
                if (r < 0)
                        return NULL;
                break;
        }

        rr->to_string = s;
        return TAKE_PTR(s);
}

ssize_t dns_resource_record_payload(DnsResourceRecord *rr, void **out) {
        assert(rr);
        assert(out);

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {
        case DNS_TYPE_SRV:
        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
        case DNS_TYPE_HINFO:
        case DNS_TYPE_SPF:
        case DNS_TYPE_TXT:
        case DNS_TYPE_A:
        case DNS_TYPE_AAAA:
        case DNS_TYPE_SOA:
        case DNS_TYPE_MX:
        case DNS_TYPE_LOC:
        case DNS_TYPE_DS:
        case DNS_TYPE_DNSKEY:
        case DNS_TYPE_RRSIG:
        case DNS_TYPE_NSEC:
        case DNS_TYPE_NSEC3:
                return -EINVAL;

        case DNS_TYPE_SSHFP:
                *out = rr->sshfp.fingerprint;
                return rr->sshfp.fingerprint_size;

        case DNS_TYPE_TLSA:
                *out = rr->tlsa.data;
                return rr->tlsa.data_size;

        case DNS_TYPE_OPENPGPKEY:
        default:
                *out = rr->generic.data;
                return rr->generic.data_size;
        }
}

int dns_resource_record_to_wire_format(DnsResourceRecord *rr, bool canonical) {

        _cleanup_(dns_packet_unref) DnsPacket packet = {
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

        r = dns_packet_append_rr(&packet, rr, 0, &start, &rds);
        if (r < 0)
                return r;

        assert(start == 0);
        assert(packet._data);

        free(rr->wire_format);
        rr->wire_format = TAKE_PTR(packet._data);
        rr->wire_format_size = packet.size;
        rr->wire_format_rdata_offset = rds;
        rr->wire_format_canonical = canonical;

        return 0;
}

int dns_resource_record_signer(DnsResourceRecord *rr, const char **ret) {
        const char *n;
        int r;

        assert(rr);
        assert(ret);

        /* Returns the RRset's signer, if it is known. */

        if (rr->n_skip_labels_signer == UINT8_MAX)
                return -ENODATA;

        n = dns_resource_key_name(rr->key);
        r = dns_name_skip(n, rr->n_skip_labels_signer, &n);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        *ret = n;
        return 0;
}

int dns_resource_record_source(DnsResourceRecord *rr, const char **ret) {
        const char *n;
        int r;

        assert(rr);
        assert(ret);

        /* Returns the RRset's synthesizing source, if it is known. */

        if (rr->n_skip_labels_source == UINT8_MAX)
                return -ENODATA;

        n = dns_resource_key_name(rr->key);
        r = dns_name_skip(n, rr->n_skip_labels_source, &n);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        *ret = n;
        return 0;
}

int dns_resource_record_is_signer(DnsResourceRecord *rr, const char *zone) {
        const char *signer;
        int r;

        assert(rr);

        r = dns_resource_record_signer(rr, &signer);
        if (r < 0)
                return r;

        return dns_name_equal(zone, signer);
}

int dns_resource_record_is_synthetic(DnsResourceRecord *rr) {
        int r;

        assert(rr);

        /* Returns > 0 if the RR is generated from a wildcard, and is not the asterisk name itself */

        if (rr->n_skip_labels_source == UINT8_MAX)
                return -ENODATA;

        if (rr->n_skip_labels_source == 0)
                return 0;

        if (rr->n_skip_labels_source > 1)
                return 1;

        r = dns_name_startswith(dns_resource_key_name(rr->key), "*");
        if (r < 0)
                return r;

        return !r;
}

void dns_resource_record_hash_func(const DnsResourceRecord *rr, struct siphash *state) {
        assert(rr);

        dns_resource_key_hash_func(rr->key, state);

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                siphash24_compress_typesafe(rr->srv.priority, state);
                siphash24_compress_typesafe(rr->srv.weight, state);
                siphash24_compress_typesafe(rr->srv.port, state);
                dns_name_hash_func(rr->srv.name, state);
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                dns_name_hash_func(rr->ptr.name, state);
                break;

        case DNS_TYPE_HINFO:
                string_hash_func(rr->hinfo.cpu, state);
                string_hash_func(rr->hinfo.os, state);
                break;

        case DNS_TYPE_TXT:
        case DNS_TYPE_SPF: {
                LIST_FOREACH(items, j, rr->txt.items) {
                        siphash24_compress_safe(j->data, j->length, state);

                        /* Add an extra NUL byte, so that "a" followed by "b" doesn't result in the same hash as "ab"
                         * followed by "". */
                        siphash24_compress_byte(0, state);
                }
                break;
        }

        case DNS_TYPE_A:
                siphash24_compress_typesafe(rr->a.in_addr, state);
                break;

        case DNS_TYPE_AAAA:
                siphash24_compress_typesafe(rr->aaaa.in6_addr, state);
                break;

        case DNS_TYPE_SOA:
                dns_name_hash_func(rr->soa.mname, state);
                dns_name_hash_func(rr->soa.rname, state);
                siphash24_compress_typesafe(rr->soa.serial, state);
                siphash24_compress_typesafe(rr->soa.refresh, state);
                siphash24_compress_typesafe(rr->soa.retry, state);
                siphash24_compress_typesafe(rr->soa.expire, state);
                siphash24_compress_typesafe(rr->soa.minimum, state);
                break;

        case DNS_TYPE_MX:
                siphash24_compress_typesafe(rr->mx.priority, state);
                dns_name_hash_func(rr->mx.exchange, state);
                break;

        case DNS_TYPE_LOC:
                siphash24_compress_typesafe(rr->loc.version, state);
                siphash24_compress_typesafe(rr->loc.size, state);
                siphash24_compress_typesafe(rr->loc.horiz_pre, state);
                siphash24_compress_typesafe(rr->loc.vert_pre, state);
                siphash24_compress_typesafe(rr->loc.latitude, state);
                siphash24_compress_typesafe(rr->loc.longitude, state);
                siphash24_compress_typesafe(rr->loc.altitude, state);
                break;

        case DNS_TYPE_SSHFP:
                siphash24_compress_typesafe(rr->sshfp.algorithm, state);
                siphash24_compress_typesafe(rr->sshfp.fptype, state);
                siphash24_compress_safe(rr->sshfp.fingerprint, rr->sshfp.fingerprint_size, state);
                break;

        case DNS_TYPE_DNSKEY:
                siphash24_compress_typesafe(rr->dnskey.flags, state);
                siphash24_compress_typesafe(rr->dnskey.protocol, state);
                siphash24_compress_typesafe(rr->dnskey.algorithm, state);
                siphash24_compress_safe(rr->dnskey.key, rr->dnskey.key_size, state);
                break;

        case DNS_TYPE_RRSIG:
                siphash24_compress_typesafe(rr->rrsig.type_covered, state);
                siphash24_compress_typesafe(rr->rrsig.algorithm, state);
                siphash24_compress_typesafe(rr->rrsig.labels, state);
                siphash24_compress_typesafe(rr->rrsig.original_ttl, state);
                siphash24_compress_typesafe(rr->rrsig.expiration, state);
                siphash24_compress_typesafe(rr->rrsig.inception, state);
                siphash24_compress_typesafe(rr->rrsig.key_tag, state);
                dns_name_hash_func(rr->rrsig.signer, state);
                siphash24_compress_safe(rr->rrsig.signature, rr->rrsig.signature_size, state);
                break;

        case DNS_TYPE_NSEC:
                dns_name_hash_func(rr->nsec.next_domain_name, state);
                /* FIXME: we leave out the type bitmap here. Hash
                 * would be better if we'd take it into account
                 * too. */
                break;

        case DNS_TYPE_DS:
                siphash24_compress_typesafe(rr->ds.key_tag, state);
                siphash24_compress_typesafe(rr->ds.algorithm, state);
                siphash24_compress_typesafe(rr->ds.digest_type, state);
                siphash24_compress_safe(rr->ds.digest, rr->ds.digest_size, state);
                break;

        case DNS_TYPE_NSEC3:
                siphash24_compress_typesafe(rr->nsec3.algorithm, state);
                siphash24_compress_typesafe(rr->nsec3.flags, state);
                siphash24_compress_typesafe(rr->nsec3.iterations, state);
                siphash24_compress_safe(rr->nsec3.salt, rr->nsec3.salt_size, state);
                siphash24_compress_safe(rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size, state);
                /* FIXME: We leave the bitmaps out */
                break;

        case DNS_TYPE_TLSA:
                siphash24_compress_typesafe(rr->tlsa.cert_usage, state);
                siphash24_compress_typesafe(rr->tlsa.selector, state);
                siphash24_compress_typesafe(rr->tlsa.matching_type, state);
                siphash24_compress_safe(rr->tlsa.data, rr->tlsa.data_size, state);
                break;

        case DNS_TYPE_CAA:
                siphash24_compress_typesafe(rr->caa.flags, state);
                string_hash_func(rr->caa.tag, state);
                siphash24_compress_safe(rr->caa.value, rr->caa.value_size, state);
                break;

        case DNS_TYPE_OPENPGPKEY:
        default:
                siphash24_compress_safe(rr->generic.data, rr->generic.data_size, state);
                break;
        }
}

int dns_resource_record_compare_func(const DnsResourceRecord *x, const DnsResourceRecord *y) {
        int r;

        r = dns_resource_key_compare_func(x->key, y->key);
        if (r != 0)
                return r;

        if (dns_resource_record_payload_equal(x, y) > 0)
                return 0;

        /* We still use CMP() here, even though don't implement proper
         * ordering, since the hashtable doesn't need ordering anyway. */
        return CMP(x, y);
}

DEFINE_HASH_OPS(dns_resource_record_hash_ops, DnsResourceRecord, dns_resource_record_hash_func, dns_resource_record_compare_func);

DnsResourceRecord *dns_resource_record_copy(DnsResourceRecord *rr) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *copy = NULL;
        DnsResourceRecord *t;

        assert(rr);

        copy = dns_resource_record_new(rr->key);
        if (!copy)
                return NULL;

        copy->ttl = rr->ttl;
        copy->expiry = rr->expiry;
        copy->n_skip_labels_signer = rr->n_skip_labels_signer;
        copy->n_skip_labels_source = rr->n_skip_labels_source;
        copy->unparsable = rr->unparsable;

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                copy->srv.priority = rr->srv.priority;
                copy->srv.weight = rr->srv.weight;
                copy->srv.port = rr->srv.port;
                copy->srv.name = strdup(rr->srv.name);
                if (!copy->srv.name)
                        return NULL;
                break;

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                copy->ptr.name = strdup(rr->ptr.name);
                if (!copy->ptr.name)
                        return NULL;
                break;

        case DNS_TYPE_HINFO:
                copy->hinfo.cpu = strdup(rr->hinfo.cpu);
                if (!copy->hinfo.cpu)
                        return NULL;

                copy->hinfo.os = strdup(rr->hinfo.os);
                if (!copy->hinfo.os)
                        return NULL;
                break;

        case DNS_TYPE_TXT:
        case DNS_TYPE_SPF:
                copy->txt.items = dns_txt_item_copy(rr->txt.items);
                if (!copy->txt.items)
                        return NULL;
                break;

        case DNS_TYPE_A:
                copy->a = rr->a;
                break;

        case DNS_TYPE_AAAA:
                copy->aaaa = rr->aaaa;
                break;

        case DNS_TYPE_SOA:
                copy->soa.mname = strdup(rr->soa.mname);
                if (!copy->soa.mname)
                        return NULL;
                copy->soa.rname = strdup(rr->soa.rname);
                if (!copy->soa.rname)
                        return NULL;
                copy->soa.serial = rr->soa.serial;
                copy->soa.refresh = rr->soa.refresh;
                copy->soa.retry = rr->soa.retry;
                copy->soa.expire = rr->soa.expire;
                copy->soa.minimum = rr->soa.minimum;
                break;

        case DNS_TYPE_MX:
                copy->mx.priority = rr->mx.priority;
                copy->mx.exchange = strdup(rr->mx.exchange);
                if (!copy->mx.exchange)
                        return NULL;
                break;

        case DNS_TYPE_LOC:
                copy->loc = rr->loc;
                break;

        case DNS_TYPE_SSHFP:
                copy->sshfp.algorithm = rr->sshfp.algorithm;
                copy->sshfp.fptype = rr->sshfp.fptype;
                copy->sshfp.fingerprint = memdup(rr->sshfp.fingerprint, rr->sshfp.fingerprint_size);
                if (!copy->sshfp.fingerprint)
                        return NULL;
                copy->sshfp.fingerprint_size = rr->sshfp.fingerprint_size;
                break;

        case DNS_TYPE_DNSKEY:
                copy->dnskey.flags = rr->dnskey.flags;
                copy->dnskey.protocol = rr->dnskey.protocol;
                copy->dnskey.algorithm = rr->dnskey.algorithm;
                copy->dnskey.key = memdup(rr->dnskey.key, rr->dnskey.key_size);
                if (!copy->dnskey.key)
                        return NULL;
                copy->dnskey.key_size = rr->dnskey.key_size;
                break;

        case DNS_TYPE_RRSIG:
                copy->rrsig.type_covered = rr->rrsig.type_covered;
                copy->rrsig.algorithm = rr->rrsig.algorithm;
                copy->rrsig.labels = rr->rrsig.labels;
                copy->rrsig.original_ttl = rr->rrsig.original_ttl;
                copy->rrsig.expiration = rr->rrsig.expiration;
                copy->rrsig.inception = rr->rrsig.inception;
                copy->rrsig.key_tag = rr->rrsig.key_tag;
                copy->rrsig.signer = strdup(rr->rrsig.signer);
                if (!copy->rrsig.signer)
                        return NULL;
                copy->rrsig.signature = memdup(rr->rrsig.signature, rr->rrsig.signature_size);
                if (!copy->rrsig.signature)
                        return NULL;
                copy->rrsig.signature_size = rr->rrsig.signature_size;
                break;

        case DNS_TYPE_NSEC:
                copy->nsec.next_domain_name = strdup(rr->nsec.next_domain_name);
                if (!copy->nsec.next_domain_name)
                        return NULL;
                if (rr->nsec.types) {
                        copy->nsec.types = bitmap_copy(rr->nsec.types);
                        if (!copy->nsec.types)
                                return NULL;
                }
                break;

        case DNS_TYPE_DS:
                copy->ds.key_tag = rr->ds.key_tag;
                copy->ds.algorithm = rr->ds.algorithm;
                copy->ds.digest_type = rr->ds.digest_type;
                copy->ds.digest = memdup(rr->ds.digest, rr->ds.digest_size);
                if (!copy->ds.digest)
                        return NULL;
                copy->ds.digest_size = rr->ds.digest_size;
                break;

        case DNS_TYPE_NSEC3:
                copy->nsec3.algorithm = rr->nsec3.algorithm;
                copy->nsec3.flags = rr->nsec3.flags;
                copy->nsec3.iterations = rr->nsec3.iterations;
                copy->nsec3.salt = memdup(rr->nsec3.salt, rr->nsec3.salt_size);
                if (!copy->nsec3.salt)
                        return NULL;
                copy->nsec3.salt_size = rr->nsec3.salt_size;
                copy->nsec3.next_hashed_name = memdup(rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size);
                if (!copy->nsec3.next_hashed_name)
                        return NULL;
                copy->nsec3.next_hashed_name_size = rr->nsec3.next_hashed_name_size;
                if (rr->nsec3.types) {
                        copy->nsec3.types = bitmap_copy(rr->nsec3.types);
                        if (!copy->nsec3.types)
                                return NULL;
                }
                break;

        case DNS_TYPE_TLSA:
                copy->tlsa.cert_usage = rr->tlsa.cert_usage;
                copy->tlsa.selector = rr->tlsa.selector;
                copy->tlsa.matching_type = rr->tlsa.matching_type;
                copy->tlsa.data = memdup(rr->tlsa.data, rr->tlsa.data_size);
                if (!copy->tlsa.data)
                        return NULL;
                copy->tlsa.data_size = rr->tlsa.data_size;
                break;

        case DNS_TYPE_CAA:
                copy->caa.flags = rr->caa.flags;
                copy->caa.tag = strdup(rr->caa.tag);
                if (!copy->caa.tag)
                        return NULL;
                copy->caa.value = memdup(rr->caa.value, rr->caa.value_size);
                if (!copy->caa.value)
                        return NULL;
                copy->caa.value_size = rr->caa.value_size;
                break;

        case DNS_TYPE_SVCB:
        case DNS_TYPE_HTTPS:
                copy->svcb.priority = rr->svcb.priority;
                copy->svcb.target_name = strdup(rr->svcb.target_name);
                if (!copy->svcb.target_name)
                        return NULL;
                copy->svcb.params = dns_svc_params_copy(rr->svcb.params);
                if (rr->svcb.params && !copy->svcb.params)
                        return NULL;
                break;

        case DNS_TYPE_OPT:
        default:
                copy->generic.data = memdup(rr->generic.data, rr->generic.data_size);
                if (!copy->generic.data)
                        return NULL;
                copy->generic.data_size = rr->generic.data_size;
                break;
        }

        t = TAKE_PTR(copy);

        return t;
}

int dns_resource_record_clamp_ttl(DnsResourceRecord **rr, uint32_t max_ttl) {
        DnsResourceRecord *old_rr, *new_rr;
        uint32_t new_ttl;

        assert(rr);
        old_rr = *rr;

        if (old_rr->key->type == DNS_TYPE_OPT)
                return -EINVAL;

        new_ttl = MIN(old_rr->ttl, max_ttl);
        if (new_ttl == old_rr->ttl)
                return 0;

        if (old_rr->n_ref == 1) {
                /* Patch in place */
                old_rr->ttl = new_ttl;
                return 1;
        }

        new_rr = dns_resource_record_copy(old_rr);
        if (!new_rr)
                return -ENOMEM;

        new_rr->ttl = new_ttl;

        DNS_RR_REPLACE(*rr, new_rr);
        return 1;
}

bool dns_resource_record_is_link_local_address(DnsResourceRecord *rr) {
        assert(rr);

        if (rr->key->class != DNS_CLASS_IN)
                return false;

        if (rr->key->type == DNS_TYPE_A)
                return in4_addr_is_link_local(&rr->a.in_addr);

        if (rr->key->type == DNS_TYPE_AAAA)
                return in6_addr_is_link_local(&rr->aaaa.in6_addr);

        return false;
}

int dns_resource_record_get_cname_target(DnsResourceKey *key, DnsResourceRecord *cname, char **ret) {
        _cleanup_free_ char *d = NULL;
        int r;

        assert(key);
        assert(cname);

        /* Checks if the RR `cname` is a CNAME/DNAME RR that matches the specified `key`. If so, returns the
         * target domain. If not, returns -EUNATCH */

        if (key->class != cname->key->class && key->class != DNS_CLASS_ANY)
                return -EUNATCH;

        if (!dns_type_may_redirect(key->type)) /* This key type is not subject to CNAME/DNAME redirection?
                                                * Then let's refuse right-away */
                return -EUNATCH;

        if (cname->key->type == DNS_TYPE_CNAME) {
                r = dns_name_equal(dns_resource_key_name(key),
                                   dns_resource_key_name(cname->key));
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EUNATCH; /* CNAME RR key doesn't actually match the original key */

                d = strdup(cname->cname.name);
                if (!d)
                        return -ENOMEM;

        } else if (cname->key->type == DNS_TYPE_DNAME) {

                r = dns_name_change_suffix(
                                dns_resource_key_name(key),
                                dns_resource_key_name(cname->key),
                                cname->dname.name,
                                &d);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EUNATCH; /* DNAME RR key doesn't actually match the original key */

        } else
                return -EUNATCH; /* Not a CNAME/DNAME RR, hence doesn't match the proposition either */

        *ret = TAKE_PTR(d);
        return 0;
}

DnsTxtItem *dns_txt_item_free_all(DnsTxtItem *first) {
        LIST_FOREACH(items, i, first)
                free(i);

        return NULL;
}

DnsSvcParam *dns_svc_param_free_all(DnsSvcParam *first) {
        LIST_FOREACH(params, i, first)
                free(i);

        return NULL;
}

bool dns_txt_item_equal(DnsTxtItem *a, DnsTxtItem *b) {
        DnsTxtItem *bb = b;

        if (a == b)
                return true;

        LIST_FOREACH(items, aa, a) {
                if (!bb)
                        return false;

                if (memcmp_nn(aa->data, aa->length, bb->data, bb->length) != 0)
                        return false;

                bb = bb->items_next;
        }

        return !bb;
}

DnsTxtItem *dns_txt_item_copy(DnsTxtItem *first) {
        DnsTxtItem *copy = NULL, *end = NULL;

        LIST_FOREACH(items, i, first) {
                DnsTxtItem *j;

                j = memdup(i, offsetof(DnsTxtItem, data) + i->length + 1);
                if (!j)
                        return dns_txt_item_free_all(copy);

                LIST_INSERT_AFTER(items, copy, end, j);
                end = j;
        }

        return copy;
}

bool dns_svc_params_equal(DnsSvcParam *a, DnsSvcParam *b) {
        DnsSvcParam *bb = b;

        if (a == b)
                return true;

        LIST_FOREACH(params, aa, a) {
                if (!bb)
                        return false;

                if (aa->key != bb->key)
                        return false;

                if (memcmp_nn(aa->value, aa->length, bb->value, bb->length) != 0)
                        return false;

                bb = bb->params_next;
        }

        return !bb;
}

DnsSvcParam *dns_svc_params_copy(DnsSvcParam *first) {
        DnsSvcParam *copy = NULL, *end = NULL;

        LIST_FOREACH(params, i, first) {
                DnsSvcParam *j;

                j = memdup(i, offsetof(DnsSvcParam, value) + i->length);
                if (!j)
                        return dns_svc_param_free_all(copy);

                LIST_INSERT_AFTER(params, copy, end, j);
                end = j;
        }

        return copy;
}

int dns_txt_item_new_empty(DnsTxtItem **ret) {
        DnsTxtItem *i;

        assert(ret);

        /* RFC 6763, section 6.1 suggests to treat
         * empty TXT RRs as equivalent to a TXT record
         * with a single empty string. */

        i = malloc0(offsetof(DnsTxtItem, data) + 1); /* for safety reasons we add an extra NUL byte */
        if (!i)
                return -ENOMEM;

        *ret = i;
        return 0;
}

int dns_resource_record_new_from_raw(DnsResourceRecord **ret, const void *data, size_t size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        int r;

        r = dns_packet_new(&p, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        p->refuse_compression = true;

        r = dns_packet_append_blob(p, data, size, NULL);
        if (r < 0)
                return r;

        return dns_packet_read_rr(p, ret, NULL, NULL);
}

int dns_resource_key_to_json(DnsResourceKey *key, JsonVariant **ret) {
        assert(key);
        assert(ret);

        return json_build(ret,
                          JSON_BUILD_OBJECT(
                                          JSON_BUILD_PAIR("class", JSON_BUILD_INTEGER(key->class)),
                                          JSON_BUILD_PAIR("type", JSON_BUILD_INTEGER(key->type)),
                                          JSON_BUILD_PAIR("name", JSON_BUILD_STRING(dns_resource_key_name(key)))));
}

int dns_resource_key_from_json(JsonVariant *v, DnsResourceKey **ret) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        uint16_t type = 0, class = 0;
        const char *name = NULL;
        int r;

        JsonDispatch dispatch_table[] = {
                { "class", _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint16,       PTR_TO_SIZE(&class), JSON_MANDATORY },
                { "type",  _JSON_VARIANT_TYPE_INVALID, json_dispatch_uint16,       PTR_TO_SIZE(&type),  JSON_MANDATORY },
                { "name",  JSON_VARIANT_STRING,        json_dispatch_const_string, PTR_TO_SIZE(&name),  JSON_MANDATORY },
                {}
        };

        assert(v);
        assert(ret);

        r = json_dispatch(v, dispatch_table, 0, NULL);
        if (r < 0)
                return r;

        key = dns_resource_key_new(class, type, name);
        if (!key)
                return -ENOMEM;

        *ret = TAKE_PTR(key);
        return 0;
}

static int type_bitmap_to_json(Bitmap *b, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *l = NULL;
        unsigned t;
        int r;

        assert(ret);

        BITMAP_FOREACH(t, b) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                r = json_variant_new_unsigned(&v, t);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&l, v);
                if (r < 0)
                        return r;
        }

        if (!l)
                return json_variant_new_array(ret, NULL, 0);

        *ret = TAKE_PTR(l);
        return 0;
}

static int txt_to_json(DnsTxtItem *items, JsonVariant **ret) {
        JsonVariant **elements = NULL;
        size_t n = 0;
        int r;

        assert(ret);

        LIST_FOREACH(items, i, items) {
                if (!GREEDY_REALLOC(elements, n + 1)) {
                        r = -ENOMEM;
                        goto finalize;
                }

                r = json_variant_new_octescape(elements + n, i->data, i->length);
                if (r < 0)
                        goto finalize;

                n++;
        }

        r = json_variant_new_array(ret, elements, n);

finalize:
        for (size_t i = 0; i < n; i++)
                json_variant_unref(elements[i]);

        free(elements);
        return r;
}

int dns_resource_record_to_json(DnsResourceRecord *rr, JsonVariant **ret) {
        _cleanup_(json_variant_unrefp) JsonVariant *k = NULL;
        int r;

        assert(rr);
        assert(ret);

        r = dns_resource_key_to_json(rr->key, &k);
        if (r < 0)
                return r;

        switch (rr->unparsable ? _DNS_TYPE_INVALID : rr->key->type) {

        case DNS_TYPE_SRV:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("priority", JSON_BUILD_UNSIGNED(rr->srv.priority)),
                                                  JSON_BUILD_PAIR("weight", JSON_BUILD_UNSIGNED(rr->srv.weight)),
                                                  JSON_BUILD_PAIR("port", JSON_BUILD_UNSIGNED(rr->srv.port)),
                                                  JSON_BUILD_PAIR("name", JSON_BUILD_STRING(rr->srv.name))));

        case DNS_TYPE_PTR:
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_DNAME:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("name", JSON_BUILD_STRING(rr->ptr.name))));

        case DNS_TYPE_HINFO:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("cpu", JSON_BUILD_STRING(rr->hinfo.cpu)),
                                                  JSON_BUILD_PAIR("os", JSON_BUILD_STRING(rr->hinfo.os))));

        case DNS_TYPE_SPF:
        case DNS_TYPE_TXT: {
                _cleanup_(json_variant_unrefp) JsonVariant *l = NULL;

                r = txt_to_json(rr->txt.items, &l);
                if (r < 0)
                        return r;

                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("items", JSON_BUILD_VARIANT(l))));
        }

        case DNS_TYPE_A:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("address", JSON_BUILD_IN4_ADDR(&rr->a.in_addr))));

        case DNS_TYPE_AAAA:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("address", JSON_BUILD_IN6_ADDR(&rr->aaaa.in6_addr))));

        case DNS_TYPE_SOA:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("mname", JSON_BUILD_STRING(rr->soa.mname)),
                                                  JSON_BUILD_PAIR("rname", JSON_BUILD_STRING(rr->soa.rname)),
                                                  JSON_BUILD_PAIR("serial", JSON_BUILD_UNSIGNED(rr->soa.serial)),
                                                  JSON_BUILD_PAIR("refresh", JSON_BUILD_UNSIGNED(rr->soa.refresh)),
                                                  JSON_BUILD_PAIR("expire", JSON_BUILD_UNSIGNED(rr->soa.retry)),
                                                  JSON_BUILD_PAIR("minimum", JSON_BUILD_UNSIGNED(rr->soa.minimum))));

        case DNS_TYPE_MX:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("priority", JSON_BUILD_UNSIGNED(rr->mx.priority)),
                                                  JSON_BUILD_PAIR("exchange", JSON_BUILD_STRING(rr->mx.exchange))));
        case DNS_TYPE_LOC:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("version", JSON_BUILD_UNSIGNED(rr->loc.version)),
                                                  JSON_BUILD_PAIR("size", JSON_BUILD_UNSIGNED(rr->loc.size)),
                                                  JSON_BUILD_PAIR("horiz_pre", JSON_BUILD_UNSIGNED(rr->loc.horiz_pre)),
                                                  JSON_BUILD_PAIR("vert_pre", JSON_BUILD_UNSIGNED(rr->loc.vert_pre)),
                                                  JSON_BUILD_PAIR("latitude", JSON_BUILD_UNSIGNED(rr->loc.latitude)),
                                                  JSON_BUILD_PAIR("longitude", JSON_BUILD_UNSIGNED(rr->loc.longitude)),
                                                  JSON_BUILD_PAIR("altitude", JSON_BUILD_UNSIGNED(rr->loc.altitude))));

        case DNS_TYPE_DS:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("keyTag", JSON_BUILD_UNSIGNED(rr->ds.key_tag)),
                                                  JSON_BUILD_PAIR("algorithm", JSON_BUILD_UNSIGNED(rr->ds.algorithm)),
                                                  JSON_BUILD_PAIR("digestType", JSON_BUILD_UNSIGNED(rr->ds.digest_type)),
                                                  JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(rr->ds.digest, rr->ds.digest_size))));

        case DNS_TYPE_SSHFP:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("algorithm", JSON_BUILD_UNSIGNED(rr->sshfp.algorithm)),
                                                  JSON_BUILD_PAIR("fptype", JSON_BUILD_UNSIGNED(rr->sshfp.fptype)),
                                                  JSON_BUILD_PAIR("fingerprint", JSON_BUILD_HEX(rr->sshfp.fingerprint, rr->sshfp.fingerprint_size))));

        case DNS_TYPE_DNSKEY:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(rr->dnskey.flags)),
                                                  JSON_BUILD_PAIR("protocol", JSON_BUILD_UNSIGNED(rr->dnskey.protocol)),
                                                  JSON_BUILD_PAIR("algorithm", JSON_BUILD_UNSIGNED(rr->dnskey.algorithm)),
                                                  JSON_BUILD_PAIR("dnskey", JSON_BUILD_BASE64(rr->dnskey.key, rr->dnskey.key_size))));


        case DNS_TYPE_RRSIG:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("signer", JSON_BUILD_STRING(rr->rrsig.signer)),
                                                  JSON_BUILD_PAIR("typeCovered", JSON_BUILD_UNSIGNED(rr->rrsig.type_covered)),
                                                  JSON_BUILD_PAIR("algorithm", JSON_BUILD_UNSIGNED(rr->rrsig.algorithm)),
                                                  JSON_BUILD_PAIR("labels", JSON_BUILD_UNSIGNED(rr->rrsig.labels)),
                                                  JSON_BUILD_PAIR("originalTtl", JSON_BUILD_UNSIGNED(rr->rrsig.original_ttl)),
                                                  JSON_BUILD_PAIR("expiration", JSON_BUILD_UNSIGNED(rr->rrsig.expiration)),
                                                  JSON_BUILD_PAIR("inception", JSON_BUILD_UNSIGNED(rr->rrsig.inception)),
                                                  JSON_BUILD_PAIR("keyTag", JSON_BUILD_UNSIGNED(rr->rrsig.key_tag)),
                                                  JSON_BUILD_PAIR("signature", JSON_BUILD_BASE64(rr->rrsig.signature, rr->rrsig.signature_size))));

        case DNS_TYPE_NSEC: {
                _cleanup_(json_variant_unrefp) JsonVariant *bm = NULL;

                r = type_bitmap_to_json(rr->nsec.types, &bm);
                if (r < 0)
                        return r;

                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("nextDomain", JSON_BUILD_STRING(rr->nsec.next_domain_name)),
                                                  JSON_BUILD_PAIR("types", JSON_BUILD_VARIANT(bm))));
        }

        case DNS_TYPE_NSEC3: {
                _cleanup_(json_variant_unrefp) JsonVariant *bm = NULL;

                r = type_bitmap_to_json(rr->nsec3.types, &bm);
                if (r < 0)
                        return r;

                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("algorithm", JSON_BUILD_UNSIGNED(rr->nsec3.algorithm)),
                                                  JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(rr->nsec3.flags)),
                                                  JSON_BUILD_PAIR("iterations", JSON_BUILD_UNSIGNED(rr->nsec3.iterations)),
                                                  JSON_BUILD_PAIR("salt", JSON_BUILD_HEX(rr->nsec3.salt, rr->nsec3.salt_size)),
                                                  JSON_BUILD_PAIR("hash", JSON_BUILD_BASE32HEX(rr->nsec3.next_hashed_name, rr->nsec3.next_hashed_name_size)),
                                                  JSON_BUILD_PAIR("types", JSON_BUILD_VARIANT(bm))));
        }

        case DNS_TYPE_TLSA:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("certUsage", JSON_BUILD_UNSIGNED(rr->tlsa.cert_usage)),
                                                  JSON_BUILD_PAIR("selector", JSON_BUILD_UNSIGNED(rr->tlsa.selector)),
                                                  JSON_BUILD_PAIR("matchingType", JSON_BUILD_UNSIGNED(rr->tlsa.matching_type)),
                                                  JSON_BUILD_PAIR("data", JSON_BUILD_HEX(rr->tlsa.data, rr->tlsa.data_size))));

        case DNS_TYPE_CAA:
                return json_build(ret,
                                  JSON_BUILD_OBJECT(
                                                  JSON_BUILD_PAIR("key", JSON_BUILD_VARIANT(k)),
                                                  JSON_BUILD_PAIR("flags", JSON_BUILD_UNSIGNED(rr->caa.flags)),
                                                  JSON_BUILD_PAIR("tag", JSON_BUILD_STRING(rr->caa.tag)),
                                                  JSON_BUILD_PAIR("value", JSON_BUILD_OCTESCAPE(rr->caa.value, rr->caa.value_size))));

        default:
                /* Can't provide broken-down format */
                *ret = NULL;
                return 0;
        }
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
        [DNSSEC_ALGORITHM_ED25519]            = "ED25519",
        [DNSSEC_ALGORITHM_ED448]              = "ED448",
        [DNSSEC_ALGORITHM_INDIRECT]           = "INDIRECT",
        [DNSSEC_ALGORITHM_PRIVATEDNS]         = "PRIVATEDNS",
        [DNSSEC_ALGORITHM_PRIVATEOID]         = "PRIVATEOID",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(dnssec_algorithm, int, 255);

static const char* const dnssec_digest_table[_DNSSEC_DIGEST_MAX_DEFINED] = {
        /* Names as listed on https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml */
        [DNSSEC_DIGEST_SHA1]            = "SHA-1",
        [DNSSEC_DIGEST_SHA256]          = "SHA-256",
        [DNSSEC_DIGEST_GOST_R_34_11_94] = "GOST_R_34.11-94",
        [DNSSEC_DIGEST_SHA384]          = "SHA-384",
};
DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(dnssec_digest, int, 255);
