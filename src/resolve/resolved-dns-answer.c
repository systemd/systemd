/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "dns-domain.h"
#include "random-util.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-dnssec.h"
#include "string-util.h"

static void dns_answer_item_hash_func(const DnsAnswerItem *a, struct siphash *state) {
        assert(a);
        assert(state);

        siphash24_compress(&a->ifindex, sizeof(a->ifindex), state);

        dns_resource_record_hash_func(a->rr, state);
}

static int dns_answer_item_compare_func(const DnsAnswerItem *a, const DnsAnswerItem *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        return dns_resource_record_compare_func(a->rr, b->rr);
}

DEFINE_PRIVATE_HASH_OPS(dns_answer_item_hash_ops, DnsAnswerItem, dns_answer_item_hash_func, dns_answer_item_compare_func);

DnsAnswer *dns_answer_new(size_t n) {
        _cleanup_set_free_ Set *s = NULL;
        DnsAnswer *a;

        if (n > UINT16_MAX) /* We can only place 64K RRs in an answer at max */
                n = UINT16_MAX;

        s = set_new(&dns_answer_item_hash_ops);
        if (!s)
                return NULL;

        /* Higher multipliers give slightly higher efficiency through hash collisions, but the gains
         * quickly drop off after 2. */
        if (set_reserve(s, n * 2) < 0)
                return NULL;

        a = malloc0(offsetof(DnsAnswer, items) + sizeof(DnsAnswerItem) * n);
        if (!a)
                return NULL;

        a->n_ref = 1;
        a->n_allocated = n;
        a->set_items = TAKE_PTR(s);
        return a;
}

static void dns_answer_flush(DnsAnswer *a) {
        DnsAnswerItem *item;

        if (!a)
                return;

        a->set_items = set_free(a->set_items);

        DNS_ANSWER_FOREACH_ITEM(item, a) {
                dns_resource_record_unref(item->rr);
                dns_resource_record_unref(item->rrsig);
        }

        a->n_rrs = 0;
}

static DnsAnswer *dns_answer_free(DnsAnswer *a) {
        assert(a);

        dns_answer_flush(a);
        return mfree(a);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsAnswer, dns_answer, dns_answer_free);

static int dns_answer_add_raw(
                DnsAnswer *a,
                DnsResourceRecord *rr,
                int ifindex,
                DnsAnswerFlags flags,
                DnsResourceRecord *rrsig) {

        int r;

        assert(rr);

        if (!a)
                return -ENOSPC;

        if (a->n_rrs >= a->n_allocated)
                return -ENOSPC;

        a->items[a->n_rrs] = (DnsAnswerItem) {
                .rr = rr,
                .ifindex = ifindex,
                .flags = flags,
                .rrsig = dns_resource_record_ref(rrsig),
        };

        r = set_put(a->set_items, &a->items[a->n_rrs]);
        if (r < 0)
                return r;
        if (r == 0)
                return -EEXIST;

        dns_resource_record_ref(rr);
        a->n_rrs++;

        return 1;
}

static int dns_answer_add_raw_all(DnsAnswer *a, DnsAnswer *source) {
        DnsAnswerItem *item;
        int r;

        DNS_ANSWER_FOREACH_ITEM(item, source) {
                r = dns_answer_add_raw(
                                a,
                                item->rr,
                                item->ifindex,
                                item->flags,
                                item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_add(
                DnsAnswer *a,
                DnsResourceRecord *rr,
                int ifindex,
                DnsAnswerFlags flags,
                DnsResourceRecord *rrsig) {

        DnsAnswerItem tmp, *exist;

        assert(rr);

        if (!a)
                return -ENOSPC;
        if (a->n_ref > 1)
                return -EBUSY;

        tmp = (DnsAnswerItem) {
                .rr = rr,
                .ifindex = ifindex,
        };

        exist = set_get(a->set_items, &tmp);
        if (exist) {
                /* There's already an RR of the same RRset in place! Let's see if the TTLs more or less
                 * match. We don't really care if they match precisely, but we do care whether one is 0 and
                 * the other is not. See RFC 2181, Section 5.2. */
                if ((rr->ttl == 0) != (exist->rr->ttl == 0))
                        return -EINVAL;

                /* Entry already exists, keep the entry with the higher TTL. */
                if (rr->ttl > exist->rr->ttl) {
                        dns_resource_record_ref(rr);
                        dns_resource_record_unref(exist->rr);
                        exist->rr = rr;

                        /* Update RRSIG and RR at the same time */
                        if (rrsig) {
                                dns_resource_record_ref(rrsig);
                                dns_resource_record_unref(exist->rrsig);
                                exist->rrsig = rrsig;
                        }
                }

                exist->flags |= flags;
                return 0;
        }

        return dns_answer_add_raw(a, rr, ifindex, flags, rrsig);
}

static int dns_answer_add_all(DnsAnswer *a, DnsAnswer *b) {
        DnsAnswerItem *item;
        int r;

        DNS_ANSWER_FOREACH_ITEM(item, b) {
                r = dns_answer_add(a, item->rr, item->ifindex, item->flags, item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_add_extend(
                DnsAnswer **a,
                DnsResourceRecord *rr,
                int ifindex,
                DnsAnswerFlags flags,
                DnsResourceRecord *rrsig) {

        int r;

        assert(a);
        assert(rr);

        r = dns_answer_reserve_or_clone(a, 1);
        if (r < 0)
                return r;

        return dns_answer_add(*a, rr, ifindex, flags, rrsig);
}

int dns_answer_add_soa(DnsAnswer *a, const char *name, uint32_t ttl, int ifindex) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *soa = NULL;

        soa = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, name);
        if (!soa)
                return -ENOMEM;

        soa->ttl = ttl;

        soa->soa.mname = strdup(name);
        if (!soa->soa.mname)
                return -ENOMEM;

        soa->soa.rname = strjoin("root.", name);
        if (!soa->soa.rname)
                return -ENOMEM;

        soa->soa.serial = 1;
        soa->soa.refresh = 1;
        soa->soa.retry = 1;
        soa->soa.expire = 1;
        soa->soa.minimum = ttl;

        return dns_answer_add(a, soa, ifindex, DNS_ANSWER_AUTHENTICATED, NULL);
}

int dns_answer_match_key(DnsAnswer *a, const DnsResourceKey *key, DnsAnswerFlags *ret_flags) {
        DnsAnswerFlags flags = 0, i_flags;
        DnsResourceRecord *i;
        bool found = false;
        int r;

        assert(key);

        DNS_ANSWER_FOREACH_FLAGS(i, i_flags, a) {
                r = dns_resource_key_match_rr(key, i, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!ret_flags)
                        return 1;

                if (found)
                        flags &= i_flags;
                else {
                        flags = i_flags;
                        found = true;
                }
        }

        if (ret_flags)
                *ret_flags = flags;

        return found;
}

bool dns_answer_contains_nsec_or_nsec3(DnsAnswer *a) {
        DnsResourceRecord *i;

        DNS_ANSWER_FOREACH(i, a)
                if (IN_SET(i->key->type, DNS_TYPE_NSEC, DNS_TYPE_NSEC3))
                        return true;

        return false;
}

int dns_answer_contains_zone_nsec3(DnsAnswer *answer, const char *zone) {
        DnsResourceRecord *rr;
        int r;

        /* Checks whether the specified answer contains at least one NSEC3 RR in the specified zone */

        DNS_ANSWER_FOREACH(rr, answer) {
                const char *p;

                if (rr->key->type != DNS_TYPE_NSEC3)
                        continue;

                p = dns_resource_key_name(rr->key);
                r = dns_name_parent(&p);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dns_name_equal(p, zone);
                if (r != 0)
                        return r;
        }

        return false;
}

bool dns_answer_contains(DnsAnswer *answer, DnsResourceRecord *rr) {
        DnsResourceRecord *i;

        DNS_ANSWER_FOREACH(i, answer)
                if (dns_resource_record_equal(i, rr))
                        return true;

        return false;
}

int dns_answer_find_soa(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsResourceRecord **ret,
                DnsAnswerFlags *ret_flags) {

        DnsResourceRecord *rr, *soa = NULL;
        DnsAnswerFlags rr_flags, soa_flags = 0;
        int r;

        assert(key);

        /* For a SOA record we can never find a matching SOA record */
        if (key->type == DNS_TYPE_SOA)
                goto not_found;

        DNS_ANSWER_FOREACH_FLAGS(rr, rr_flags, a) {
                r = dns_resource_key_match_soa(key, rr->key);
                if (r < 0)
                        return r;
                if (r > 0) {

                        if (soa) {
                                r = dns_name_endswith(dns_resource_key_name(rr->key), dns_resource_key_name(soa->key));
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        continue;
                        }

                        soa = rr;
                        soa_flags = rr_flags;
                }
        }

        if (!soa)
                goto not_found;

        if (ret)
                *ret = soa;
        if (ret_flags)
                *ret_flags = soa_flags;

        return 1;

not_found:
        if (ret)
                *ret = NULL;
        if (ret_flags)
                *ret_flags = 0;

        return 0;
}

int dns_answer_find_cname_or_dname(
                DnsAnswer *a,
                const DnsResourceKey *key,
                DnsResourceRecord **ret,
                DnsAnswerFlags *ret_flags) {

        DnsResourceRecord *rr;
        DnsAnswerFlags rr_flags;
        int r;

        assert(key);

        /* For a {C,D}NAME record we can never find a matching {C,D}NAME record */
        if (!dns_type_may_redirect(key->type))
                return 0;

        DNS_ANSWER_FOREACH_FLAGS(rr, rr_flags, a) {
                r = dns_resource_key_match_cname_or_dname(key, rr->key, NULL);
                if (r < 0)
                        return r;
                if (r > 0) {
                        if (ret)
                                *ret = rr;
                        if (ret_flags)
                                *ret_flags = rr_flags;
                        return 1;
                }
        }

        if (ret)
                *ret = NULL;
        if (ret_flags)
                *ret_flags = 0;

        return 0;
}

int dns_answer_merge(DnsAnswer *a, DnsAnswer *b, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *k = NULL;
        int r;

        assert(ret);

        if (a == b) {
                *ret = dns_answer_ref(a);
                return 0;
        }

        if (dns_answer_size(a) <= 0) {
                *ret = dns_answer_ref(b);
                return 0;
        }

        if (dns_answer_size(b) <= 0) {
                *ret = dns_answer_ref(a);
                return 0;
        }

        k = dns_answer_new(a->n_rrs + b->n_rrs);
        if (!k)
                return -ENOMEM;

        r = dns_answer_add_raw_all(k, a);
        if (r < 0)
                return r;

        r = dns_answer_add_all(k, b);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(k);

        return 0;
}

int dns_answer_extend(DnsAnswer **a, DnsAnswer *b) {
        DnsAnswer *merged;
        int r;

        assert(a);

        r = dns_answer_merge(*a, b, &merged);
        if (r < 0)
                return r;

        dns_answer_unref(*a);
        *a = merged;

        return 0;
}

int dns_answer_remove_by_key(DnsAnswer **a, const DnsResourceKey *key) {
        bool found = false, other = false;
        DnsResourceRecord *rr;
        size_t i;
        int r;

        assert(a);
        assert(key);

        /* Remove all entries matching the specified key from *a */

        DNS_ANSWER_FOREACH(rr, *a) {
                r = dns_resource_key_equal(rr->key, key);
                if (r < 0)
                        return r;
                if (r > 0)
                        found = true;
                else
                        other = true;

                if (found && other)
                        break;
        }

        if (!found)
                return 0;

        if (!other) {
                *a = dns_answer_unref(*a); /* Return NULL for the empty answer */
                return 1;
        }

        if ((*a)->n_ref > 1) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *copy = NULL;
                DnsAnswerItem *item;

                copy = dns_answer_new((*a)->n_rrs);
                if (!copy)
                        return -ENOMEM;

                DNS_ANSWER_FOREACH_ITEM(item, *a) {
                        r = dns_resource_key_equal(item->rr->key, key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = dns_answer_add_raw(copy, item->rr, item->ifindex, item->flags, item->rrsig);
                        if (r < 0)
                                return r;
                }

                dns_answer_unref(*a);
                *a = TAKE_PTR(copy);

                return 1;
        }

        /* Only a single reference, edit in-place */

        i = 0;
        for (;;) {
                if (i >= (*a)->n_rrs)
                        break;

                r = dns_resource_key_equal((*a)->items[i].rr->key, key);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Kill this entry */

                        dns_resource_record_unref((*a)->items[i].rr);
                        dns_resource_record_unref((*a)->items[i].rrsig);

                        memmove((*a)->items + i, (*a)->items + i + 1, sizeof(DnsAnswerItem) * ((*a)->n_rrs - i - 1));
                        (*a)->n_rrs--;
                        continue;

                } else
                        /* Keep this entry */
                        i++;
        }

        return 1;
}

int dns_answer_remove_by_rr(DnsAnswer **a, DnsResourceRecord *rm) {
        bool found = false, other = false;
        DnsResourceRecord *rr;
        size_t i;
        int r;

        assert(a);
        assert(rm);

        /* Remove all entries matching the specified RR from *a */

        DNS_ANSWER_FOREACH(rr, *a) {
                r = dns_resource_record_equal(rr, rm);
                if (r < 0)
                        return r;
                if (r > 0)
                        found = true;
                else
                        other = true;

                if (found && other)
                        break;
        }

        if (!found)
                return 0;

        if (!other) {
                *a = dns_answer_unref(*a); /* Return NULL for the empty answer */
                return 1;
        }

        if ((*a)->n_ref > 1) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *copy = NULL;
                DnsAnswerItem *item;

                copy = dns_answer_new((*a)->n_rrs);
                if (!copy)
                        return -ENOMEM;

                DNS_ANSWER_FOREACH_ITEM(item, *a) {
                        r = dns_resource_record_equal(item->rr, rm);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = dns_answer_add_raw(copy, item->rr, item->ifindex, item->flags, item->rrsig);
                        if (r < 0)
                                return r;
                }

                dns_answer_unref(*a);
                *a = TAKE_PTR(copy);

                return 1;
        }

        /* Only a single reference, edit in-place */

        i = 0;
        for (;;) {
                if (i >= (*a)->n_rrs)
                        break;

                r = dns_resource_record_equal((*a)->items[i].rr, rm);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Kill this entry */

                        dns_resource_record_unref((*a)->items[i].rr);
                        dns_resource_record_unref((*a)->items[i].rrsig);
                        memmove((*a)->items + i, (*a)->items + i + 1, sizeof(DnsAnswerItem) * ((*a)->n_rrs - i - 1));
                        (*a)->n_rrs--;
                        continue;

                } else
                        /* Keep this entry */
                        i++;
        }

        return 1;
}

int dns_answer_remove_by_answer_keys(DnsAnswer **a, DnsAnswer *b) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *prev = NULL;
        DnsAnswerItem *item;
        int r;

        /* Removes all items from '*a' that have a matching key in 'b' */

        DNS_ANSWER_FOREACH_ITEM(item, b) {

                if (prev && dns_resource_key_equal(item->rr->key, prev)) /* Skip this one, we already looked at it */
                        continue;

                r = dns_answer_remove_by_key(a, item->rr->key);
                if (r < 0)
                        return r;

                /* Let's remember this entry's RR key, to optimize the loop a bit: if we have an RRset with
                 * more than one item then we don't need to remove the key multiple times */
                dns_resource_key_unref(prev);
                prev = dns_resource_key_ref(item->rr->key);
        }

        return 0;
}

int dns_answer_copy_by_key(
                DnsAnswer **a,
                DnsAnswer *source,
                const DnsResourceKey *key,
                DnsAnswerFlags or_flags,
                DnsResourceRecord *rrsig) {

        DnsAnswerItem *item;
        int r;

        assert(a);
        assert(key);

        /* Copy all RRs matching the specified key from source into *a */

        DNS_ANSWER_FOREACH_ITEM(item, source) {

                r = dns_resource_key_equal(item->rr->key, key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* Make space for at least one entry */
                r = dns_answer_reserve_or_clone(a, 1);
                if (r < 0)
                        return r;

                r = dns_answer_add(*a, item->rr, item->ifindex, item->flags|or_flags, rrsig ?: item->rrsig);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_move_by_key(
                DnsAnswer **to,
                DnsAnswer **from,
                const DnsResourceKey *key,
                DnsAnswerFlags or_flags,
                DnsResourceRecord *rrsig) {
        int r;

        assert(to);
        assert(from);
        assert(key);

        r = dns_answer_copy_by_key(to, *from, key, or_flags, rrsig);
        if (r < 0)
                return r;

        return dns_answer_remove_by_key(from, key);
}

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local) {
        DnsAnswerItem *items;
        size_t i, start, end;

        if (!a)
                return;

        if (a->n_rrs <= 1)
                return;

        start = 0;
        end = a->n_rrs-1;

        /* RFC 4795, Section 2.6 suggests we should order entries
         * depending on whether the sender is a link-local address. */

        items = newa(DnsAnswerItem, a->n_rrs);
        for (i = 0; i < a->n_rrs; i++) {
                if (dns_resource_record_is_link_local_address(a->items[i].rr) != prefer_link_local)
                        /* Order address records that are not preferred to the end of the array */
                        items[end--] = a->items[i];
                else
                        /* Order all other records to the beginning of the array */
                        items[start++] = a->items[i];
        }

        assert(start == end+1);
        memcpy(a->items, items, sizeof(DnsAnswerItem) * a->n_rrs);
}

int dns_answer_reserve(DnsAnswer **a, size_t n_free) {
        DnsAnswer *n;

        assert(a);

        if (n_free <= 0)
                return 0;

        if (*a) {
                size_t ns;
                int r;

                if ((*a)->n_ref > 1)
                        return -EBUSY;

                ns = (*a)->n_rrs;
                assert(ns <= UINT16_MAX); /* Maximum number of RRs we can stick into a DNS packet section */

                if (n_free > UINT16_MAX - ns) /* overflow check */
                        ns = UINT16_MAX;
                else
                        ns += n_free;

                if ((*a)->n_allocated >= ns)
                        return 0;

                /* Allocate more than we need, but not more than UINT16_MAX */
                if (ns <= UINT16_MAX/2)
                        ns *= 2;
                else
                        ns = UINT16_MAX;

                /* This must be done before realloc() below. Otherwise, the original DnsAnswer object
                 * may be broken. */
                r = set_reserve((*a)->set_items, ns);
                if (r < 0)
                        return r;

                n = realloc(*a, offsetof(DnsAnswer, items) + sizeof(DnsAnswerItem) * ns);
                if (!n)
                        return -ENOMEM;

                n->n_allocated = ns;

                /* Previously all items are stored in the set, and the enough memory area is allocated
                 * in the above. So set_put() in the below cannot fail. */
                set_clear(n->set_items);
                for (size_t i = 0; i < n->n_rrs; i++)
                        assert_se(set_put(n->set_items, &n->items[i]) > 0);
        } else {
                n = dns_answer_new(n_free);
                if (!n)
                        return -ENOMEM;
        }

        *a = n;
        return 0;
}

int dns_answer_reserve_or_clone(DnsAnswer **a, size_t n_free) {
        int r;

        assert(a);

        /* Tries to extend the DnsAnswer object. And if that's not possible, since we are not the sole owner,
         * then allocate a new, appropriately sized one. Either way, after this call the object will only
         * have a single reference, and has room for at least the specified number of RRs. */

        if (*a && (*a)->n_ref > 1) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *n = NULL;
                size_t ns;

                ns = (*a)->n_rrs;
                assert(ns <= UINT16_MAX); /* Maximum number of RRs we can stick into a DNS packet section */

                if (n_free > UINT16_MAX - ns) /* overflow check */
                        ns = UINT16_MAX;
                else if (n_free > 0) { /* Increase size and double the result, just in case — except if the
                                        * increase is specified as 0, in which case we just allocate the
                                        * exact amount as before, under the assumption this is just a request
                                        * to copy the answer. */
                        ns += n_free;

                        if (ns <= UINT16_MAX/2) /* overflow check */
                                ns *= 2;
                        else
                                ns = UINT16_MAX;
                }

                n = dns_answer_new(ns);
                if (!n)
                        return -ENOMEM;

                r = dns_answer_add_raw_all(n, *a);
                if (r < 0)
                        return r;

                dns_answer_unref(*a);
                assert_se(*a = TAKE_PTR(n));
        } else if (n_free > 0) {
                r = dns_answer_reserve(a, n_free);
                if (r < 0)
                        return r;
        }

        return 0;
}

/*
 * This function is not used in the code base, but is useful when debugging. Do not delete.
 */
void dns_answer_dump(DnsAnswer *answer, FILE *f) {
        DnsAnswerItem *item;

        if (!f)
                f = stdout;

        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                const char *t;

                fputc('\t', f);

                t = dns_resource_record_to_string(item->rr);
                if (!t) {
                        log_oom();
                        continue;
                }

                fputs(t, f);
                fputs("\t;", f);
                fprintf(f, " ttl=%" PRIu32, item->rr->ttl);

                if (item->ifindex != 0)
                        fprintf(f, " ifindex=%i", item->ifindex);
                if (item->rrsig)
                        fputs(" rrsig", f);
                if (item->flags & DNS_ANSWER_AUTHENTICATED)
                        fputs(" authenticated", f);
                if (item->flags & DNS_ANSWER_CACHEABLE)
                        fputs(" cacheable", f);
                if (item->flags & DNS_ANSWER_SHARED_OWNER)
                        fputs(" shared-owner", f);
                if (item->flags & DNS_ANSWER_CACHE_FLUSH)
                        fputs(" cache-flush", f);
                if (item->flags & DNS_ANSWER_GOODBYE)
                        fputs(" goodbye", f);
                if (item->flags & DNS_ANSWER_SECTION_ANSWER)
                        fputs(" section-answer", f);
                if (item->flags & DNS_ANSWER_SECTION_AUTHORITY)
                        fputs(" section-authority", f);
                if (item->flags & DNS_ANSWER_SECTION_ADDITIONAL)
                        fputs(" section-additional", f);

                fputc('\n', f);
        }
}

int dns_answer_has_dname_for_cname(DnsAnswer *a, DnsResourceRecord *cname) {
        DnsResourceRecord *rr;
        int r;

        assert(cname);

        /* Checks whether the answer contains a DNAME record that indicates that the specified CNAME record is
         * synthesized from it */

        if (cname->key->type != DNS_TYPE_CNAME)
                return 0;

        DNS_ANSWER_FOREACH(rr, a) {
                _cleanup_free_ char *n = NULL;

                if (rr->key->type != DNS_TYPE_DNAME)
                        continue;
                if (rr->key->class != cname->key->class)
                        continue;

                r = dns_name_change_suffix(cname->cname.name, rr->dname.name, dns_resource_key_name(rr->key), &n);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = dns_name_equal(n, dns_resource_key_name(cname->key));
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

void dns_answer_randomize(DnsAnswer *a) {
        size_t n;

        /* Permutes the answer list randomly (Knuth shuffle) */

        n = dns_answer_size(a);
        if (n <= 1)
                return;

        for (size_t i = 0; i < n; i++) {
                size_t k;

                k = random_u64_range(n);
                if (k == i)
                        continue;

                SWAP_TWO(a->items[i], a->items[k]);
        }
}

uint32_t dns_answer_min_ttl(DnsAnswer *a) {
        uint32_t ttl = UINT32_MAX;
        DnsResourceRecord *rr;

        /* Return the smallest TTL of all RRs in this answer */

        DNS_ANSWER_FOREACH(rr, a) {
                /* Don't consider OPT (where the TTL field is used for other purposes than an actual TTL) */

                if (dns_type_is_pseudo(rr->key->type) ||
                    dns_class_is_pseudo(rr->key->class))
                        continue;

                ttl = MIN(ttl, rr->ttl);
        }

        return ttl;
}
