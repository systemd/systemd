/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-type.h"
#include "resolved-dns-question.h"
#include "socket-util.h"

DnsQuestion *dns_question_new(size_t n) {
        DnsQuestion *q;

        if (n > UINT16_MAX) /* We can only place 64K key in an question section at max */
                n = UINT16_MAX;

        q = malloc0(offsetof(DnsQuestion, items) + sizeof(DnsQuestionItem) * n);
        if (!q)
                return NULL;

        q->n_ref = 1;
        q->n_allocated = n;

        return q;
}

static DnsQuestion *dns_question_free(DnsQuestion *q) {
        DnsResourceKey *key;

        assert(q);

        DNS_QUESTION_FOREACH(key, q)
                dns_resource_key_unref(key);

        return mfree(q);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsQuestion, dns_question, dns_question_free);

int dns_question_add_raw(DnsQuestion *q, DnsResourceKey *key, DnsQuestionFlags flags) {
        /* Insert without checking for duplicates. */

        assert(key);
        assert(q);

        if (q->n_keys >= q->n_allocated)
                return -ENOSPC;

        q->items[q->n_keys++] = (DnsQuestionItem) {
                .key = dns_resource_key_ref(key),
                .flags = flags,
        };
        return 0;
}

static int dns_question_add_raw_all(DnsQuestion *a, DnsQuestion *b) {
        DnsQuestionItem *item;
        int r;

        DNS_QUESTION_FOREACH_ITEM(item, b) {
                r = dns_question_add_raw(a, item->key, item->flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_question_add(DnsQuestion *q, DnsResourceKey *key, DnsQuestionFlags flags) {
        DnsQuestionItem *item;
        int r;

        assert(key);

        if (!q)
                return -ENOSPC;


        DNS_QUESTION_FOREACH_ITEM(item, q) {
                r = dns_resource_key_equal(item->key, key);
                if (r < 0)
                        return r;
                if (r > 0 && item->flags == flags)
                        return 0;
        }

        return dns_question_add_raw(q, key, flags);
}

static int dns_question_add_all(DnsQuestion *a, DnsQuestion *b) {
        DnsQuestionItem *item;
        int r;

        DNS_QUESTION_FOREACH_ITEM(item, b) {
                r = dns_question_add(a, item->key, item->flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_question_matches_rr(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain) {
        DnsResourceKey *key;
        int r;

        assert(rr);

        if (!q)
                return 0;

        DNS_QUESTION_FOREACH(key, q) {
                r = dns_resource_key_match_rr(key, rr, search_domain);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_matches_cname_or_dname(DnsQuestion *q, DnsResourceRecord *rr, const char *search_domain) {
        DnsResourceKey *key;
        int r;

        assert(rr);

        if (!q)
                return 0;

        if (!IN_SET(rr->key->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME))
                return 0;

        DNS_QUESTION_FOREACH(key, q) {
                /* For a {C,D}NAME record we can never find a matching {C,D}NAME record */
                if (!dns_type_may_redirect(key->type))
                        return 0;

                r = dns_resource_key_match_cname_or_dname(key, rr->key, search_domain);
                if (r != 0)
                        return r;
        }

        return 0;
}

int dns_question_is_valid_for_query(DnsQuestion *q) {
        const char *name;
        size_t i;
        int r;

        if (!q)
                return 0;

        if (q->n_keys <= 0)
                return 0;

        if (q->n_keys > 65535)
                return 0;

        name = dns_resource_key_name(q->items[0].key);
        if (!name)
                return 0;

        /* Check that all keys in this question bear the same name */
        for (i = 0; i < q->n_keys; i++) {
                assert(q->items[i].key);

                if (i > 0) {
                        r = dns_name_equal(dns_resource_key_name(q->items[i].key), name);
                        if (r <= 0)
                                return r;
                }

                if (!dns_type_is_valid_query(q->items[i].key->type))
                        return 0;
        }

        return 1;
}

int dns_question_contains_key(DnsQuestion *q, const DnsResourceKey *k) {
        size_t j;
        int r;

        assert(k);

        if (!q)
                return 0;


        for (j = 0; j < q->n_keys; j++) {
                r = dns_resource_key_equal(q->items[j].key, k);
                if (r != 0)
                        return r;
        }

        return 0;
}

static int dns_question_contains_item(DnsQuestion *q, const DnsQuestionItem *i) {
        DnsQuestionItem *item;
        int r;

        assert(i);

        DNS_QUESTION_FOREACH_ITEM(item, q) {
                if (item->flags != i->flags)
                        continue;
                r = dns_resource_key_equal(item->key, i->key);
                if (r != 0)
                        return r;
        }

        return false;
}

int dns_question_is_equal(DnsQuestion *a, DnsQuestion *b) {
        DnsQuestionItem *item;
        int r;

        if (a == b)
                return 1;

        if (!a)
                return !b || b->n_keys == 0;
        if (!b)
                return a->n_keys == 0;

        /* Checks if all items in a are also contained b, and vice versa */

        DNS_QUESTION_FOREACH_ITEM(item, a) {
                r = dns_question_contains_item(b, item);
                if (r <= 0)
                        return r;
        }
        DNS_QUESTION_FOREACH_ITEM(item, b) {
                r = dns_question_contains_item(a, item);
                if (r <= 0)
                        return r;
        }

        return 1;
}

int dns_question_cname_redirect(DnsQuestion *q, const DnsResourceRecord *cname, DnsQuestion **ret) {
        _cleanup_(dns_question_unrefp) DnsQuestion *n = NULL;
        DnsResourceKey *key;
        bool same = true;
        int r;

        assert(cname);
        assert(ret);
        assert(IN_SET(cname->key->type, DNS_TYPE_CNAME, DNS_TYPE_DNAME));

        if (dns_question_size(q) <= 0) {
                *ret = NULL;
                return 0;
        }

        DNS_QUESTION_FOREACH(key, q) {
                _cleanup_free_ char *destination = NULL;
                const char *d;

                if (cname->key->type == DNS_TYPE_CNAME)
                        d = cname->cname.name;
                else {
                        r = dns_name_change_suffix(dns_resource_key_name(key), dns_resource_key_name(cname->key), cname->dname.name, &destination);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        d = destination;
                }

                r = dns_name_equal(dns_resource_key_name(key), d);
                if (r < 0)
                        return r;

                if (r == 0) {
                        same = false;
                        break;
                }
        }

        /* Fully the same, indicate we didn't do a thing */
        if (same) {
                *ret = NULL;
                return 0;
        }

        n = dns_question_new(q->n_keys);
        if (!n)
                return -ENOMEM;

        /* Create a new question, and patch in the new name */
        DNS_QUESTION_FOREACH(key, q) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *k = NULL;

                k = dns_resource_key_new_redirect(key, cname);
                if (!k)
                        return -ENOMEM;

                r = dns_question_add(n, k, 0);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(n);

        return 1;
}

const char *dns_question_first_name(DnsQuestion *q) {

        if (!q)
                return NULL;

        if (q->n_keys < 1)
                return NULL;

        return dns_resource_key_name(q->items[0].key);
}

int dns_question_new_address(DnsQuestion **ret, int family, const char *name, bool convert_idna) {
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        assert(ret);
        assert(name);

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return -EAFNOSUPPORT;

        /* If IPv6 is off and the request has an unspecified lookup family, restrict it automatically to
         * IPv4. */
        if (family == AF_UNSPEC && !socket_ipv6_is_enabled())
                family = AF_INET;

        if (convert_idna) {
                r = dns_name_apply_idna(name, &buf);
                if (r < 0)
                        return r;
                if (r > 0 && !streq(name, buf))
                        name = buf;
                else
                        /* We did not manage to create convert the idna name, or it's
                         * the same as the original name. We assume the caller already
                         * created an unconverted question, so let's not repeat work
                         * unnecessarily. */
                        return -EALREADY;
        }

        q = dns_question_new(family == AF_UNSPEC ? 2 : 1);
        if (!q)
                return -ENOMEM;

        if (family != AF_INET6) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key, 0);
                if (r < 0)
                        return r;
        }

        if (family != AF_INET) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key, 0);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(q);

        return 0;
}

int dns_question_new_reverse(DnsQuestion **ret, int family, const union in_addr_union *a) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_free_ char *reverse = NULL;
        int r;

        assert(ret);
        assert(a);

        if (!IN_SET(family, AF_INET, AF_INET6, AF_UNSPEC))
                return -EAFNOSUPPORT;

        r = dns_name_reverse(family, a, &reverse);
        if (r < 0)
                return r;

        q = dns_question_new(1);
        if (!q)
                return -ENOMEM;

        key = dns_resource_key_new_consume(DNS_CLASS_IN, DNS_TYPE_PTR, reverse);
        if (!key)
                return -ENOMEM;

        reverse = NULL;

        r = dns_question_add(q, key, 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(q);

        return 0;
}

int dns_question_new_service_type(
                DnsQuestion **ret,
                const char *service,
                const char *type,
                const char *domain,
                bool convert_idna,
                uint16_t record_type) {

        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_free_ char *buf = NULL, *joined = NULL;
        const char *name;
        int r;

        assert(ret);

        if (record_type == DNS_TYPE_SRV)
                return -EINVAL;

        if (!domain)
                return -EINVAL;

        if (type) {
                if (convert_idna) {
                        r = dns_name_apply_idna(domain, &buf);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                domain = buf;
                }

                r = dns_service_join(service, type, domain, &joined);
                if (r < 0)
                        return r;

                name = joined;
        } else {
                if (service)
                        return -EINVAL;

                name = domain;
        }

        q = dns_question_new(1);
        if (!q)
                return -ENOMEM;

        key = dns_resource_key_new(DNS_CLASS_IN, record_type, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(q, key, 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(q);

        return 0;
}

int dns_question_new_service(
                DnsQuestion **ret,
                const char *service,
                const char *type,
                const char *domain,
                bool with_txt,
                bool convert_idna) {

        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *q = NULL;
        _cleanup_free_ char *buf = NULL, *joined = NULL;
        const char *name;
        int r;

        assert(ret);

        /* We support three modes of invocation:
         *
         * 1. Only a domain is specified, in which case we assume a properly encoded SRV RR name, including service
         *    type and possibly a service name. If specified in this way we assume it's already IDNA converted if
         *    that's necessary.
         *
         * 2. Both service type and a domain specified, in which case a normal SRV RR is assumed, without a DNS-SD
         *    style prefix. In this case we'll IDNA convert the domain, if that's requested.
         *
         * 3. All three of service name, type and domain are specified, in which case a DNS-SD service is put
         *    together. The service name is never IDNA converted, and the domain is if requested.
         *
         * It's not supported to specify a service name without a type, or no domain name.
         */

        if (!domain)
                return -EINVAL;

        if (type) {
                if (convert_idna) {
                        r = dns_name_apply_idna(domain, &buf);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                domain = buf;
                }

                r = dns_service_join(service, type, domain, &joined);
                if (r < 0)
                        return r;

                name = joined;
        } else {
                if (service)
                        return -EINVAL;

                name = domain;
        }

        q = dns_question_new(1 + with_txt);
        if (!q)
                return -ENOMEM;

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_SRV, name);
        if (!key)
                return -ENOMEM;

        r = dns_question_add(q, key, 0);
        if (r < 0)
                return r;

        if (with_txt) {
                dns_resource_key_unref(key);
                key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_TXT, name);
                if (!key)
                        return -ENOMEM;

                r = dns_question_add(q, key, 0);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(q);

        return 0;
}

/*
 * This function is not used in the code base, but is useful when debugging. Do not delete.
 */
void dns_question_dump(DnsQuestion *question, FILE *f) {
        DnsResourceKey *k;

        if (!f)
                f = stdout;

        DNS_QUESTION_FOREACH(k, question) {
                char buf[DNS_RESOURCE_KEY_STRING_MAX];

                fputc('\t', f);
                fputs(dns_resource_key_to_string(k, buf, sizeof(buf)), f);
                fputc('\n', f);
        }
}

int dns_question_merge(DnsQuestion *a, DnsQuestion *b, DnsQuestion **ret) {
        _cleanup_(dns_question_unrefp) DnsQuestion *k = NULL;
        int r;

        assert(ret);

        if (a == b || dns_question_size(b) <= 0) {
                *ret = dns_question_ref(a);
                return 0;
        }

        if (dns_question_size(a) <= 0) {
                *ret = dns_question_ref(b);
                return 0;
        }

        k = dns_question_new(dns_question_size(a) + dns_question_size(b));
        if (!k)
                return -ENOMEM;

        r = dns_question_add_raw_all(k, a);
        if (r < 0)
                return r;

        r = dns_question_add_all(k, b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(k);
        return 0;
}
