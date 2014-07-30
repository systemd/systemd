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

#include "list.h"

#include "resolved-dns-zone.h"
#include "resolved-dns-domain.h"
#include "resolved-dns-packet.h"

/* Never allow more than 1K entries */
#define ZONE_MAX 1024

typedef struct DnsZoneItem DnsZoneItem;

struct DnsZoneItem {
        DnsResourceRecord *rr;
        bool verified;
        LIST_FIELDS(DnsZoneItem, by_key);
        LIST_FIELDS(DnsZoneItem, by_name);
};

static void dns_zone_item_free(DnsZoneItem *i) {
        if (!i)
                return;

        dns_resource_record_unref(i->rr);
        free(i);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DnsZoneItem*, dns_zone_item_free);

static void dns_zone_item_remove_and_free(DnsZone *z, DnsZoneItem *i) {
        DnsZoneItem *first;

        assert(z);

        if (!i)
                return;

        first = hashmap_get(z->by_key, i->rr->key);
        LIST_REMOVE(by_key, first, i);
        if (first)
                assert_se(hashmap_replace(z->by_key, first->rr->key, first) >= 0);
        else
                hashmap_remove(z->by_key, i->rr->key);

        first = hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(i->rr->key));
        LIST_REMOVE(by_name, first, i);
        if (first)
                assert_se(hashmap_replace(z->by_name, DNS_RESOURCE_KEY_NAME(first->rr->key), first) >= 0);
        else
                hashmap_remove(z->by_name, DNS_RESOURCE_KEY_NAME(i->rr->key));

        dns_zone_item_free(i);
}

void dns_zone_flush(DnsZone *z) {
        DnsZoneItem *i;

        assert(z);

        while ((i = hashmap_first(z->by_key)))
                dns_zone_item_remove_and_free(z, i);

        assert(hashmap_size(z->by_key) == 0);
        assert(hashmap_size(z->by_name) == 0);

        hashmap_free(z->by_key);
        z->by_key = NULL;

        hashmap_free(z->by_name);
        z->by_name = NULL;
}

static DnsZoneItem* dns_zone_get(DnsZone *z, DnsResourceRecord *rr) {
        DnsZoneItem *i;

        assert(z);
        assert(rr);

        LIST_FOREACH(by_key, i, hashmap_get(z->by_key, rr->key))
                if (dns_resource_record_equal(i->rr, rr))
                        return i;

        return NULL;
}

void dns_zone_remove_rr(DnsZone *z, DnsResourceRecord *rr) {
        DnsZoneItem *i;

        assert(z);
        assert(rr);

        i = dns_zone_get(z, rr);
        if (i)
                dns_zone_item_remove_and_free(z, i);
}

static int dns_zone_init(DnsZone *z) {
        int r;

        assert(z);

        r = hashmap_ensure_allocated(&z->by_key, dns_resource_key_hash_func, dns_resource_key_compare_func);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&z->by_name, dns_name_hash_func, dns_name_compare_func);
        if (r < 0)
                return r;

        return 0;
}

static int dns_zone_link_item(DnsZone *z, DnsZoneItem *i) {
        DnsZoneItem *first;
        int r;

        first = hashmap_get(z->by_key, i->rr->key);
        if (first) {
                LIST_PREPEND(by_key, first, i);
                assert_se(hashmap_replace(z->by_key, first->rr->key, first) >= 0);
        } else {
                r = hashmap_put(z->by_key, i->rr->key, i);
                if (r < 0)
                        return r;
        }

        first = hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(i->rr->key));
        if (first) {
                LIST_PREPEND(by_name, first, i);
                assert_se(hashmap_replace(z->by_name, DNS_RESOURCE_KEY_NAME(first->rr->key), first) >= 0);
        } else {
                r = hashmap_put(z->by_name, DNS_RESOURCE_KEY_NAME(i->rr->key), i);
                if (r < 0)
                        return r;
        }

        return 0;
}

int dns_zone_put(DnsZone *z, DnsResourceRecord *rr) {
        _cleanup_(dns_zone_item_freep) DnsZoneItem *i = NULL;
        DnsZoneItem *existing;
        int r;

        assert(z);
        assert(rr);

        if (rr->key->class == DNS_CLASS_ANY)
                return -EINVAL;
        if (rr->key->type == DNS_TYPE_ANY)
                return -EINVAL;

        existing = dns_zone_get(z, rr);
        if (existing)
                return 0;

        r = dns_zone_init(z);
        if (r < 0)
                return r;

        i = new0(DnsZoneItem, 1);
        if (!i)
                return -ENOMEM;

        i->rr = dns_resource_record_ref(rr);

        r = dns_zone_link_item(z, i);
        if (r < 0)
                return r;

        i = NULL;
        return 0;
}

int dns_zone_lookup(DnsZone *z, DnsQuestion *q, DnsAnswer **ret_answer, DnsAnswer **ret_soa) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        unsigned i, n_answer = 0, n_soa = 0;
        int r;

        assert(z);
        assert(q);
        assert(ret_answer);
        assert(ret_soa);

        if (q->n_keys <= 0) {
                *ret_answer = NULL;
                *ret_soa = NULL;
                return 0;
        }

        /* First iteration, count what we have */
        for (i = 0; i < q->n_keys; i++) {
                DnsZoneItem *j;

                if (q->keys[i]->type == DNS_TYPE_ANY ||
                    q->keys[i]->class == DNS_CLASS_ANY) {
                        int k;

                        /* If this is a generic match, then we have to
                         * go through the list by the name and look
                         * for everything manually */

                        j = hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(q->keys[i]));
                        LIST_FOREACH(by_name, j, j) {
                                k = dns_resource_key_match_rr(q->keys[i], j->rr);
                                if (k < 0)
                                        return k;
                                if (k == 0)
                                        n_soa++;
                                else
                                        n_answer++;
                        }

                } else {
                        j = hashmap_get(z->by_key, q->keys[i]);
                        if (j) {
                                LIST_FOREACH(by_key, j, j)
                                        n_answer++;
                        } else {
                                if (hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(q->keys[i])))
                                        n_soa ++;
                        }
                }
        }

        if (n_answer <= 0 && n_soa <= 0) {
                *ret_answer = NULL;
                *ret_soa = NULL;
                return 0;
        }

        if (n_answer > 0) {
                answer = dns_answer_new(n_answer);
                if (!answer)
                        return -ENOMEM;
        }

        if (n_soa > 0) {
                soa = dns_answer_new(n_soa);
                if (!soa)
                        return -ENOMEM;
        }

        /* Second iteration, actually add the RRs to the answers */
        for (i = 0; i < q->n_keys; i++) {
                DnsZoneItem *j;

                if (q->keys[i]->type == DNS_TYPE_ANY ||
                    q->keys[i]->class == DNS_CLASS_ANY) {
                        int k;

                        j = hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(q->keys[i]));
                        LIST_FOREACH(by_name, j, j) {
                                k = dns_resource_key_match_rr(q->keys[i], j->rr);
                                if (k < 0)
                                        return k;
                                if (k == 0)
                                        r = dns_answer_add_soa(soa, DNS_RESOURCE_KEY_NAME(q->keys[i]));
                                else
                                        r = dns_answer_add(answer, j->rr);
                                if (r < 0)
                                        return r;
                        }
                } else {

                        j = hashmap_get(z->by_key, q->keys[i]);
                        if (j) {
                                LIST_FOREACH(by_key, j, j) {
                                        r = dns_answer_add(answer, j->rr);
                                        if (r < 0)
                                                return r;
                                }
                        } else {
                                if (hashmap_get(z->by_name, DNS_RESOURCE_KEY_NAME(q->keys[i]))) {
                                        r = dns_answer_add_soa(soa, DNS_RESOURCE_KEY_NAME(q->keys[i]));
                                        if (r < 0)
                                                return r;
                                }
                        }
                }
        }

        *ret_answer = answer;
        answer = NULL;

        *ret_soa = soa;
        soa = NULL;

        return 1;
}
