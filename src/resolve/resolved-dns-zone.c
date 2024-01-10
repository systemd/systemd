/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dns-domain.h"
#include "list.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-zone.h"
#include "resolved-dnssd.h"
#include "resolved-manager.h"
#include "string-util.h"

/* Never allow more than 1K entries */
#define ZONE_MAX 1024

void dns_zone_item_probe_stop(DnsZoneItem *i) {
        DnsTransaction *t;
        assert(i);

        if (!i->probe_transaction)
                return;

        t = TAKE_PTR(i->probe_transaction);

        set_remove(t->notify_zone_items, i);
        set_remove(t->notify_zone_items_done, i);
        dns_transaction_gc(t);
}

static DnsZoneItem* dns_zone_item_free(DnsZoneItem *i) {
        if (!i)
                return NULL;

        dns_zone_item_probe_stop(i);
        dns_resource_record_unref(i->rr);

        return mfree(i);
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

        first = hashmap_get(z->by_name, dns_resource_key_name(i->rr->key));
        LIST_REMOVE(by_name, first, i);
        if (first)
                assert_se(hashmap_replace(z->by_name, dns_resource_key_name(first->rr->key), first) >= 0);
        else
                hashmap_remove(z->by_name, dns_resource_key_name(i->rr->key));

        dns_zone_item_free(i);
}

void dns_zone_flush(DnsZone *z) {
        DnsZoneItem *i;

        assert(z);

        while ((i = hashmap_first(z->by_key)))
                dns_zone_item_remove_and_free(z, i);

        assert(hashmap_isempty(z->by_key));
        assert(hashmap_isempty(z->by_name));

        z->by_key = hashmap_free(z->by_key);
        z->by_name = hashmap_free(z->by_name);
}

DnsZoneItem* dns_zone_get(DnsZone *z, DnsResourceRecord *rr) {
        assert(z);
        assert(rr);

        LIST_FOREACH(by_key, i, (DnsZoneItem*) hashmap_get(z->by_key, rr->key))
                if (dns_resource_record_equal(i->rr, rr) > 0)
                        return i;

        return NULL;
}

void dns_zone_remove_rr(DnsZone *z, DnsResourceRecord *rr) {
        DnsZoneItem *i;

        assert(z);

        if (!rr)
                return;

        i = dns_zone_get(z, rr);
        if (i)
                dns_zone_item_remove_and_free(z, i);
}

int dns_zone_remove_rrs_by_key(DnsZone *z, DnsResourceKey *key) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        DnsResourceRecord *rr;
        bool tentative;
        int r;

        r = dns_zone_lookup(z, key, 0, &answer, &soa, &tentative);
        if (r < 0)
                return r;

        DNS_ANSWER_FOREACH(rr, answer)
                dns_zone_remove_rr(z, rr);

        return 0;
}

static int dns_zone_init(DnsZone *z) {
        int r;

        assert(z);

        r = hashmap_ensure_allocated(&z->by_key, &dns_resource_key_hash_ops);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&z->by_name, &dns_name_hash_ops);
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

        first = hashmap_get(z->by_name, dns_resource_key_name(i->rr->key));
        if (first) {
                LIST_PREPEND(by_name, first, i);
                assert_se(hashmap_replace(z->by_name, dns_resource_key_name(first->rr->key), first) >= 0);
        } else {
                r = hashmap_put(z->by_name, dns_resource_key_name(i->rr->key), i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int dns_zone_item_probe_start(DnsZoneItem *i)  {
        _cleanup_(dns_transaction_gcp) DnsTransaction *t = NULL;
        int r;

        assert(i);

        if (i->probe_transaction)
                return 0;

        t = dns_scope_find_transaction(
                        i->scope,
                        &DNS_RESOURCE_KEY_CONST(i->rr->key->class, DNS_TYPE_ANY, dns_resource_key_name(i->rr->key)),
                        SD_RESOLVED_NO_CACHE|SD_RESOLVED_NO_ZONE);
        if (!t) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                key = dns_resource_key_new(i->rr->key->class, DNS_TYPE_ANY, dns_resource_key_name(i->rr->key));
                if (!key)
                        return -ENOMEM;

                r = dns_transaction_new(&t, i->scope, key, NULL, SD_RESOLVED_NO_CACHE|SD_RESOLVED_NO_ZONE);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&t->notify_zone_items_done, NULL);
        if (r < 0)
                return r;

        r = set_ensure_put(&t->notify_zone_items, NULL, i);
        if (r < 0)
                return r;

        t->probing = true;
        i->probe_transaction = TAKE_PTR(t);

        if (i->probe_transaction->state == DNS_TRANSACTION_NULL) {
                i->block_ready++;
                r = dns_transaction_go(i->probe_transaction);
                i->block_ready--;

                if (r < 0) {
                        dns_zone_item_probe_stop(i);
                        return r;
                }
        }

        dns_zone_item_notify(i);
        return 0;
}

int dns_zone_put(DnsZone *z, DnsScope *s, DnsResourceRecord *rr, bool probe) {
        _cleanup_(dns_zone_item_freep) DnsZoneItem *i = NULL;
        DnsZoneItem *existing;
        int r;

        assert(z);
        assert(s);
        assert(rr);

        if (dns_class_is_pseudo(rr->key->class))
                return -EINVAL;
        if (dns_type_is_pseudo(rr->key->type))
                return -EINVAL;

        existing = dns_zone_get(z, rr);
        if (existing)
                return 0;

        r = dns_zone_init(z);
        if (r < 0)
                return r;

        i = new(DnsZoneItem, 1);
        if (!i)
                return -ENOMEM;

        *i = (DnsZoneItem) {
                .scope = s,
                .rr = dns_resource_record_ref(rr),
                .probing_enabled = probe,
        };

        r = dns_zone_link_item(z, i);
        if (r < 0)
                return r;

        if (probe) {
                bool established = false;

                /* Check if there's already an RR with the same name
                 * established. If so, it has been probed already, and
                 * we don't need to probe again. */

                LIST_FOREACH_OTHERS(by_name, j, i)
                        if (j->state == DNS_ZONE_ITEM_ESTABLISHED)
                                established = true;

                if (established)
                        i->state = DNS_ZONE_ITEM_ESTABLISHED;
                else {
                        i->state = DNS_ZONE_ITEM_PROBING;

                        r = dns_zone_item_probe_start(i);
                        if (r < 0) {
                                dns_zone_item_remove_and_free(z, i);
                                i = NULL;
                                return r;
                        }
                }
        } else
                i->state = DNS_ZONE_ITEM_ESTABLISHED;

        i = NULL;
        return 0;
}

static int dns_zone_add_authenticated_answer(DnsAnswer *a, DnsZoneItem *i, int ifindex) {
        DnsAnswerFlags flags;

        /* From RFC 6762, Section 10.2
         * "They (the rules about when to set the cache-flush bit) apply to
         * startup announcements as described in Section 8.3, "Announcing",
         * and to responses generated as a result of receiving query messages."
         * So, set the cache-flush bit for mDNS answers except for DNS-SD
         * service enumeration PTRs described in RFC 6763, Section 4.1. */
        if (i->scope->protocol == DNS_PROTOCOL_MDNS &&
            !dns_resource_key_is_dnssd_ptr(i->rr->key))
                flags = DNS_ANSWER_AUTHENTICATED|DNS_ANSWER_CACHE_FLUSH;
        else
                flags = DNS_ANSWER_AUTHENTICATED;

        return dns_answer_add(a, i->rr, ifindex, flags, NULL);
}

int dns_zone_lookup(DnsZone *z, DnsResourceKey *key, int ifindex, DnsAnswer **ret_answer, DnsAnswer **ret_soa, bool *ret_tentative) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL, *soa = NULL;
        unsigned n_answer = 0;
        DnsZoneItem *first;
        bool tentative = true, need_soa = false;
        int r;

        /* Note that we don't actually need the ifindex for anything. However when it is passed we'll initialize the
         * ifindex field in the answer with it */

        assert(z);
        assert(key);
        assert(ret_answer);

        /* First iteration, count what we have */

        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                bool found = false, added = false;
                int k;

                /* If this is a generic match, then we have to
                 * go through the list by the name and look
                 * for everything manually */

                first = hashmap_get(z->by_name, dns_resource_key_name(key));
                LIST_FOREACH(by_name, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        k = dns_resource_key_match_rr(key, j->rr, NULL);
                        if (k < 0)
                                return k;
                        if (k > 0) {
                                n_answer++;
                                added = true;
                        }

                }

                if (found && !added)
                        need_soa = true;

        } else {
                bool found = false;

                /* If this is a specific match, then look for
                 * the right key immediately */

                first = hashmap_get(z->by_key, key);
                LIST_FOREACH(by_key, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;
                        n_answer++;
                }

                if (!found) {
                        first = hashmap_get(z->by_name, dns_resource_key_name(key));
                        LIST_FOREACH(by_name, j, first) {
                                if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                        continue;

                                need_soa = true;
                                break;
                        }
                }
        }

        if (n_answer <= 0 && !need_soa)
                goto return_empty;

        if (n_answer > 0) {
                answer = dns_answer_new(n_answer);
                if (!answer)
                        return -ENOMEM;
        }

        if (need_soa) {
                soa = dns_answer_new(1);
                if (!soa)
                        return -ENOMEM;
        }

        /* Second iteration, actually add the RRs to the answers */
        if (key->type == DNS_TYPE_ANY || key->class == DNS_CLASS_ANY) {
                bool found = false, added = false;
                int k;

                first = hashmap_get(z->by_name, dns_resource_key_name(key));
                LIST_FOREACH(by_name, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        if (j->state != DNS_ZONE_ITEM_PROBING)
                                tentative = false;

                        k = dns_resource_key_match_rr(key, j->rr, NULL);
                        if (k < 0)
                                return k;
                        if (k > 0) {
                                r = dns_zone_add_authenticated_answer(answer, j, ifindex);
                                if (r < 0)
                                        return r;

                                added = true;
                        }
                }

                if (found && !added) {
                        r = dns_answer_add_soa(soa, dns_resource_key_name(key), LLMNR_DEFAULT_TTL, ifindex);
                        if (r < 0)
                                return r;
                }
        } else {
                bool found = false;

                first = hashmap_get(z->by_key, key);
                LIST_FOREACH(by_key, j, first) {
                        if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                continue;

                        found = true;

                        if (j->state != DNS_ZONE_ITEM_PROBING)
                                tentative = false;

                        r = dns_zone_add_authenticated_answer(answer, j, ifindex);
                        if (r < 0)
                                return r;
                }

                if (!found) {
                        bool add_soa = false;

                        first = hashmap_get(z->by_name, dns_resource_key_name(key));
                        LIST_FOREACH(by_name, j, first) {
                                if (!IN_SET(j->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                                        continue;

                                if (j->state != DNS_ZONE_ITEM_PROBING)
                                        tentative = false;

                                add_soa = true;
                        }

                        if (add_soa) {
                                r = dns_answer_add_soa(soa, dns_resource_key_name(key), LLMNR_DEFAULT_TTL, ifindex);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* If the caller sets ret_tentative to NULL, then use this as
         * indication to not return tentative entries */

        if (!ret_tentative && tentative)
                goto return_empty;

        *ret_answer = TAKE_PTR(answer);

        if (ret_soa)
                *ret_soa = TAKE_PTR(soa);

        if (ret_tentative)
                *ret_tentative = tentative;

        return 1;

return_empty:
        *ret_answer = NULL;

        if (ret_soa)
                *ret_soa = NULL;

        if (ret_tentative)
                *ret_tentative = false;

        return 0;
}

void dns_zone_item_conflict(DnsZoneItem *i) {
        assert(i);

        if (!IN_SET(i->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_VERIFYING, DNS_ZONE_ITEM_ESTABLISHED))
                return;

        log_info("Detected conflict on %s", strna(dns_resource_record_to_string(i->rr)));

        dns_zone_item_probe_stop(i);

        /* Withdraw the conflict item */
        i->state = DNS_ZONE_ITEM_WITHDRAWN;

        (void) dnssd_signal_conflict(i->scope->manager, dns_resource_key_name(i->rr->key));

        /* Maybe change the hostname */
        if (manager_is_own_hostname(i->scope->manager, dns_resource_key_name(i->rr->key)) > 0)
                manager_next_hostname(i->scope->manager);
}

void dns_zone_item_notify(DnsZoneItem *i) {
        assert(i);
        assert(i->probe_transaction);

        if (i->block_ready > 0)
                return;

        if (IN_SET(i->probe_transaction->state, DNS_TRANSACTION_NULL, DNS_TRANSACTION_PENDING, DNS_TRANSACTION_VALIDATING))
                return;

        if (i->probe_transaction->state == DNS_TRANSACTION_SUCCESS) {
                bool we_lost = false;

                /* The probe got a successful reply. If we so far
                 * weren't established we just give up.
                 *
                 * In LLMNR case if we already
                 * were established, and the peer has the
                 * lexicographically larger IP address we continue
                 * and defend it. */

                if (!IN_SET(i->state, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING)) {
                        log_debug("Got a successful probe for not yet established RR, we lost.");
                        we_lost = true;
                } else if (i->probe_transaction->scope->protocol == DNS_PROTOCOL_LLMNR) {
                        assert(i->probe_transaction->received);
                        we_lost = memcmp(&i->probe_transaction->received->sender, &i->probe_transaction->received->destination, FAMILY_ADDRESS_SIZE(i->probe_transaction->received->family)) < 0;
                        if (we_lost)
                                log_debug("Got a successful probe reply for an established RR, and we have a lexicographically larger IP address and thus lost.");
                }

                if (we_lost) {
                        dns_zone_item_conflict(i);
                        return;
                }

                log_debug("Got a successful probe reply, but peer has lexicographically lower IP address and thus lost.");
        }

        log_debug("Record %s successfully probed.", strna(dns_resource_record_to_string(i->rr)));

        dns_zone_item_probe_stop(i);
        i->state = DNS_ZONE_ITEM_ESTABLISHED;
}

static int dns_zone_item_verify(DnsZoneItem *i) {
        int r;

        assert(i);

        if (i->state != DNS_ZONE_ITEM_ESTABLISHED)
                return 0;

        log_debug("Verifying RR %s", strna(dns_resource_record_to_string(i->rr)));

        i->state = DNS_ZONE_ITEM_VERIFYING;
        r = dns_zone_item_probe_start(i);
        if (r < 0) {
                log_error_errno(r, "Failed to start probing for verifying RR: %m");
                i->state = DNS_ZONE_ITEM_ESTABLISHED;
                return r;
        }

        return 0;
}

int dns_zone_check_conflicts(DnsZone *zone, DnsResourceRecord *rr) {
        DnsZoneItem *first;
        int c = 0;

        assert(zone);
        assert(rr);

        /* This checks whether a response RR we received from somebody
         * else is one that we actually thought was uniquely ours. If
         * so, we'll verify our RRs. */

        /* No conflict if we don't have the name at all. */
        first = hashmap_get(zone->by_name, dns_resource_key_name(rr->key));
        if (!first)
                return 0;

        /* No conflict if we have the exact same RR */
        if (dns_zone_get(zone, rr))
                return 0;

        /* No conflict if it is DNS-SD RR used for service enumeration. */
        if (dns_resource_key_is_dnssd_ptr(rr->key))
                return 0;

        /* OK, somebody else has RRs for the same name. Yuck! Let's
         * start probing again */

        LIST_FOREACH(by_name, i, first) {
                if (dns_resource_record_equal(i->rr, rr))
                        continue;

                dns_zone_item_verify(i);
                c++;
        }

        return c;
}

int dns_zone_verify_conflicts(DnsZone *zone, DnsResourceKey *key) {
        DnsZoneItem *first;
        int c = 0;

        assert(zone);

        /* Somebody else notified us about a possible conflict. Let's
         * verify if that's true. */

        first = hashmap_get(zone->by_name, dns_resource_key_name(key));
        if (!first)
                return 0;

        LIST_FOREACH(by_name, i, first) {
                dns_zone_item_verify(i);
                c++;
        }

        return c;
}

void dns_zone_verify_all(DnsZone *zone) {
        DnsZoneItem *i;

        assert(zone);

        HASHMAP_FOREACH(i, zone->by_key)
                LIST_FOREACH(by_key, j, i)
                        dns_zone_item_verify(j);
}

void dns_zone_dump(DnsZone *zone, FILE *f) {
        DnsZoneItem *i;

        if (!zone)
                return;

        if (!f)
                f = stdout;

        HASHMAP_FOREACH(i, zone->by_key)
                LIST_FOREACH(by_key, j, i) {
                        const char *t;

                        t = dns_resource_record_to_string(j->rr);
                        if (!t) {
                                log_oom();
                                continue;
                        }

                        fputc('\t', f);
                        fputs(t, f);
                        fputc('\n', f);
                }
}

bool dns_zone_is_empty(DnsZone *zone) {
        if (!zone)
                return true;

        return hashmap_isempty(zone->by_key);
}

bool dns_zone_contains_name(DnsZone *z, const char *name) {
        DnsZoneItem *first;

        first = hashmap_get(z->by_name, name);
        if (!first)
                return false;

        LIST_FOREACH(by_name, i, first) {
                if (!IN_SET(i->state, DNS_ZONE_ITEM_PROBING, DNS_ZONE_ITEM_ESTABLISHED, DNS_ZONE_ITEM_VERIFYING))
                        continue;

                return true;
        }

        return false;
}
