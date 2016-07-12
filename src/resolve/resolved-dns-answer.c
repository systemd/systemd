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

#include "alloc-util.h"
#include "dns-domain.h"
#include "resolved-dns-answer.h"
#include "resolved-dns-dnssec.h"
#include "string-util.h"

DnsAnswer *dns_answer_new(unsigned n) {
        DnsAnswer *a;

        a = malloc0(offsetof(DnsAnswer, items) + sizeof(DnsAnswerItem) * n);
        if (!a)
                return NULL;

        a->n_ref = 1;
        a->n_allocated = n;

        return a;
}

DnsAnswer *dns_answer_ref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);
        a->n_ref++;
        return a;
}

static void dns_answer_flush(DnsAnswer *a) {
        DnsResourceRecord *rr;

        if (!a)
                return;

        DNS_ANSWER_FOREACH(rr, a)
                dns_resource_record_unref(rr);

        a->n_rrs = 0;
}

DnsAnswer *dns_answer_unref(DnsAnswer *a) {
        if (!a)
                return NULL;

        assert(a->n_ref > 0);

        if (a->n_ref == 1) {
                dns_answer_flush(a);
                free(a);
        } else
                a->n_ref--;

        return NULL;
}

static int dns_answer_add_raw(DnsAnswer *a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags) {
        assert(rr);

        if (!a)
                return -ENOSPC;

        if (a->n_rrs >= a->n_allocated)
                return -ENOSPC;

        a->items[a->n_rrs++] = (DnsAnswerItem) {
                .rr = dns_resource_record_ref(rr),
                .ifindex = ifindex,
                .flags = flags,
        };

        return 1;
}

static int dns_answer_add_raw_all(DnsAnswer *a, DnsAnswer *source) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int ifindex, r;

        DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, source) {
                r = dns_answer_add_raw(a, rr, ifindex, flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_add(DnsAnswer *a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags) {
        unsigned i;
        int r;

        assert(rr);

        if (!a)
                return -ENOSPC;
        if (a->n_ref > 1)
                return -EBUSY;

        for (i = 0; i < a->n_rrs; i++) {
                if (a->items[i].ifindex != ifindex)
                        continue;

                r = dns_resource_record_equal(a->items[i].rr, rr);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* Don't mix contradicting TTLs (see below) */
                        if ((rr->ttl == 0) != (a->items[i].rr->ttl == 0))
                                return -EINVAL;

                        /* Entry already exists, keep the entry with
                         * the higher RR. */
                        if (rr->ttl > a->items[i].rr->ttl) {
                                dns_resource_record_ref(rr);
                                dns_resource_record_unref(a->items[i].rr);
                                a->items[i].rr = rr;
                        }

                        a->items[i].flags |= flags;
                        return 0;
                }

                r = dns_resource_key_equal(a->items[i].rr->key, rr->key);
                if (r < 0)
                        return r;
                if (r > 0) {
                        /* There's already an RR of the same RRset in
                         * place! Let's see if the TTLs more or less
                         * match. We don't really care if they match
                         * precisely, but we do care whether one is 0
                         * and the other is not. See RFC 2181, Section
                         * 5.2.*/

                        if ((rr->ttl == 0) != (a->items[i].rr->ttl == 0))
                                return -EINVAL;
                }
        }

        return dns_answer_add_raw(a, rr, ifindex, flags);
}

static int dns_answer_add_all(DnsAnswer *a, DnsAnswer *b) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int ifindex, r;

        DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, b) {
                r = dns_answer_add(a, rr, ifindex, flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_add_extend(DnsAnswer **a, DnsResourceRecord *rr, int ifindex, DnsAnswerFlags flags) {
        int r;

        assert(a);
        assert(rr);

        r = dns_answer_reserve_or_clone(a, 1);
        if (r < 0)
                return r;

        return dns_answer_add(*a, rr, ifindex, flags);
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

        soa->soa.rname = strappend("root.", name);
        if (!soa->soa.rname)
                return -ENOMEM;

        soa->soa.serial = 1;
        soa->soa.refresh = 1;
        soa->soa.retry = 1;
        soa->soa.expire = 1;
        soa->soa.minimum = ttl;

        return dns_answer_add(a, soa, ifindex, DNS_ANSWER_AUTHENTICATED);
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

int dns_answer_contains_rr(DnsAnswer *a, DnsResourceRecord *rr, DnsAnswerFlags *ret_flags) {
        DnsAnswerFlags flags = 0, i_flags;
        DnsResourceRecord *i;
        bool found = false;
        int r;

        assert(rr);

        DNS_ANSWER_FOREACH_FLAGS(i, i_flags, a) {
                r = dns_resource_record_equal(i, rr);
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

int dns_answer_contains_key(DnsAnswer *a, const DnsResourceKey *key, DnsAnswerFlags *ret_flags) {
        DnsAnswerFlags flags = 0, i_flags;
        DnsResourceRecord *i;
        bool found = false;
        int r;

        assert(key);

        DNS_ANSWER_FOREACH_FLAGS(i, i_flags, a) {
                r = dns_resource_key_equal(i->key, key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (!ret_flags)
                        return true;

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

int dns_answer_contains_nsec_or_nsec3(DnsAnswer *a) {
        DnsResourceRecord *i;

        DNS_ANSWER_FOREACH(i, a) {
                if (IN_SET(i->key->type, DNS_TYPE_NSEC, DNS_TYPE_NSEC3))
                        return true;
        }

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

int dns_answer_find_soa(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *flags) {
        DnsResourceRecord *rr, *soa = NULL;
        DnsAnswerFlags rr_flags, soa_flags = 0;
        int r;

        assert(key);

        /* For a SOA record we can never find a matching SOA record */
        if (key->type == DNS_TYPE_SOA)
                return 0;

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
                return 0;

        if (ret)
                *ret = soa;
        if (flags)
                *flags = soa_flags;

        return 1;
}

int dns_answer_find_cname_or_dname(DnsAnswer *a, const DnsResourceKey *key, DnsResourceRecord **ret, DnsAnswerFlags *flags) {
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
                        if (flags)
                                *flags = rr_flags;
                        return 1;
                }
        }

        return 0;
}

int dns_answer_merge(DnsAnswer *a, DnsAnswer *b, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *k = NULL;
        int r;

        assert(ret);

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

        *ret = k;
        k = NULL;

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
        unsigned i;
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
                DnsAnswerFlags flags;
                int ifindex;

                copy = dns_answer_new((*a)->n_rrs);
                if (!copy)
                        return -ENOMEM;

                DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, *a) {
                        r = dns_resource_key_equal(rr->key, key);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = dns_answer_add_raw(copy, rr, ifindex, flags);
                        if (r < 0)
                                return r;
                }

                dns_answer_unref(*a);
                *a = copy;
                copy = NULL;

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
        unsigned i;
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
                DnsAnswerFlags flags;
                int ifindex;

                copy = dns_answer_new((*a)->n_rrs);
                if (!copy)
                        return -ENOMEM;

                DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, *a) {
                        r = dns_resource_record_equal(rr, rm);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = dns_answer_add_raw(copy, rr, ifindex, flags);
                        if (r < 0)
                                return r;
                }

                dns_answer_unref(*a);
                *a = copy;
                copy = NULL;

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
                        memmove((*a)->items + i, (*a)->items + i + 1, sizeof(DnsAnswerItem) * ((*a)->n_rrs - i - 1));
                        (*a)->n_rrs--;
                        continue;

                } else
                        /* Keep this entry */
                        i++;
        }

        return 1;
}

int dns_answer_copy_by_key(DnsAnswer **a, DnsAnswer *source, const DnsResourceKey *key, DnsAnswerFlags or_flags) {
        DnsResourceRecord *rr_source;
        int ifindex_source, r;
        DnsAnswerFlags flags_source;

        assert(a);
        assert(key);

        /* Copy all RRs matching the specified key from source into *a */

        DNS_ANSWER_FOREACH_FULL(rr_source, ifindex_source, flags_source, source) {

                r = dns_resource_key_equal(rr_source->key, key);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* Make space for at least one entry */
                r = dns_answer_reserve_or_clone(a, 1);
                if (r < 0)
                        return r;

                r = dns_answer_add(*a, rr_source, ifindex_source, flags_source|or_flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_answer_move_by_key(DnsAnswer **to, DnsAnswer **from, const DnsResourceKey *key, DnsAnswerFlags or_flags) {
        int r;

        assert(to);
        assert(from);
        assert(key);

        r = dns_answer_copy_by_key(to, *from, key, or_flags);
        if (r < 0)
                return r;

        return dns_answer_remove_by_key(from, key);
}

void dns_answer_order_by_scope(DnsAnswer *a, bool prefer_link_local) {
        DnsAnswerItem *items;
        unsigned i, start, end;

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

                if (a->items[i].rr->key->class == DNS_CLASS_IN &&
                    ((a->items[i].rr->key->type == DNS_TYPE_A && in_addr_is_link_local(AF_INET, (union in_addr_union*) &a->items[i].rr->a.in_addr) != prefer_link_local) ||
                     (a->items[i].rr->key->type == DNS_TYPE_AAAA && in_addr_is_link_local(AF_INET6, (union in_addr_union*) &a->items[i].rr->aaaa.in6_addr) != prefer_link_local)))
                        /* Order address records that are not preferred to the end of the array */
                        items[end--] = a->items[i];
                else
                        /* Order all other records to the beginning of the array */
                        items[start++] = a->items[i];
        }

        assert(start == end+1);
        memcpy(a->items, items, sizeof(DnsAnswerItem) * a->n_rrs);
}

int dns_answer_reserve(DnsAnswer **a, unsigned n_free) {
        DnsAnswer *n;

        assert(a);

        if (n_free <= 0)
                return 0;

        if (*a) {
                unsigned ns;

                if ((*a)->n_ref > 1)
                        return -EBUSY;

                ns = (*a)->n_rrs + n_free;

                if ((*a)->n_allocated >= ns)
                        return 0;

                /* Allocate more than we need */
                ns *= 2;

                n = realloc(*a, offsetof(DnsAnswer, items) + sizeof(DnsAnswerItem) * ns);
                if (!n)
                        return -ENOMEM;

                n->n_allocated = ns;
        } else {
                n = dns_answer_new(n_free);
                if (!n)
                        return -ENOMEM;
        }

        *a = n;
        return 0;
}

int dns_answer_reserve_or_clone(DnsAnswer **a, unsigned n_free) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *n = NULL;
        int r;

        assert(a);

        /* Tries to extend the DnsAnswer object. And if that's not
         * possible, since we are not the sole owner, then allocate a
         * new, appropriately sized one. Either way, after this call
         * the object will only have a single reference, and has room
         * for at least the specified number of RRs. */

        r = dns_answer_reserve(a, n_free);
        if (r != -EBUSY)
                return r;

        assert(*a);

        n = dns_answer_new(((*a)->n_rrs + n_free) * 2);
        if (!n)
                return -ENOMEM;

        r = dns_answer_add_raw_all(n, *a);
        if (r < 0)
                return r;

        dns_answer_unref(*a);
        *a = n;
        n = NULL;

        return 0;
}

void dns_answer_dump(DnsAnswer *answer, FILE *f) {
        DnsResourceRecord *rr;
        DnsAnswerFlags flags;
        int ifindex;

        if (!f)
                f = stdout;

        DNS_ANSWER_FOREACH_FULL(rr, ifindex, flags, answer) {
                const char *t;

                fputc('\t', f);

                t = dns_resource_record_to_string(rr);
                if (!t) {
                        log_oom();
                        continue;
                }

                fputs(t, f);

                if (ifindex != 0 || flags & (DNS_ANSWER_AUTHENTICATED|DNS_ANSWER_CACHEABLE|DNS_ANSWER_SHARED_OWNER))
                        fputs("\t;", f);

                if (ifindex != 0)
                        printf(" ifindex=%i", ifindex);
                if (flags & DNS_ANSWER_AUTHENTICATED)
                        fputs(" authenticated", f);
                if (flags & DNS_ANSWER_CACHEABLE)
                        fputs(" cachable", f);
                if (flags & DNS_ANSWER_SHARED_OWNER)
                        fputs(" shared-owner", f);

                fputc('\n', f);
        }
}

bool dns_answer_has_dname_for_cname(DnsAnswer *a, DnsResourceRecord *cname) {
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
