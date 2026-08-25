/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "event-util.h"
#include "log.h"
#include "random-util.h"
#include "resolved-dns-browse-services.h"
#include "resolved-dns-cache.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-manager.h"
#include "siphash24.h"
#include "string-table.h"
#include "string-util.h"

typedef enum BrowseServiceUpdateEvent {
        BROWSE_SERVICE_UPDATE_ADDED,
        BROWSE_SERVICE_UPDATE_REMOVED,
        _BROWSE_SERVICE_UPDATE_MAX,
        _BROWSE_SERVICE_UPDATE_INVALID = -EINVAL,
} BrowseServiceUpdateEvent;

static const char * const browse_service_update_event_table[_BROWSE_SERVICE_UPDATE_MAX] = {
        [BROWSE_SERVICE_UPDATE_ADDED]   = "added",
        [BROWSE_SERVICE_UPDATE_REMOVED] = "removed",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(browse_service_update_event, BrowseServiceUpdateEvent);

/* Split the service name out of a PTR record (falling back to the record's key for a PTR target
 * that does not parse as an instance name) and append one browserServiceData event entry to the
 * JSON array. Returns > 0 when an entry was appended, 0 when the record does not describe a
 * service (no type) and nothing was appended. */
static int browse_service_update_append(
                sd_json_variant **array,
                DnsResourceRecord *rr,
                int family,
                int ifindex,
                BrowseServiceUpdateEvent event) {

        _cleanup_free_ char *name = NULL, *type = NULL, *domain = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
        int r;

        assert(array);
        assert(rr);

        /* A cache lookup for a PTR key can also hand back the CNAME/DNAME/NSEC items it followed
         * (dns_cache_get_by_key_follow_cname_dname_nsec()), and an mDNS responder does send NSEC
         * for a name it owns but has no record of this type for (RFC 6762 §6.1). Only a PTR names
         * a service instance; reading rr->ptr.name off anything else would invent one. */
        if (rr->key->type != DNS_TYPE_PTR)
                return 0;

        /* A name that does not parse as a service instance is a per-record data problem (the
         * records come off the multicast wire): skip the record like the no-type case below,
         * rather than failing the whole batch over it. Only resource errors propagate. */
        r = dns_service_split(rr->ptr.name, &name, &type, &domain);
        if (r == -ENOMEM)
                return r;
        if (r < 0)
                return 0;

        if (!name) {
                type = mfree(type);
                domain = mfree(domain);

                r = dns_service_split(dns_resource_key_name(rr->key), &name, &type, &domain);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        return 0;
        }

        if (!type)
                return 0;

        log_debug("%s browsed service %s, %s, %s, %s, %d",
                  browse_service_update_event_to_string(event),
                  strna(name),
                  strna(type),
                  strna(domain),
                  strna(af_to_ipv4_ipv6(family)),
                  ifindex);

        r = sd_json_buildo(
                        &entry,
                        SD_JSON_BUILD_PAIR_STRING(
                                        "updateFlag",
                                        browse_service_update_event_to_string(event)),
                        SD_JSON_BUILD_PAIR_INTEGER("family", family),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !isempty(name), "name", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !isempty(type), "type", SD_JSON_BUILD_STRING(type)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        !isempty(domain), "domain", SD_JSON_BUILD_STRING(domain)),
                        SD_JSON_BUILD_PAIR_INTEGER("ifindex", ifindex));
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(array, entry);
        if (r < 0)
                return r;

        return 1;
}

/* RFC6762 5.2
 * The intervals between successive queries MUST increase by at least a
 * factor of two. When the interval between queries reaches or exceeds
 * 60 minutes, perform subsequent queries at a steady-state rate of one
 * query per hour. */
static usec_t mdns_calculate_next_query_delay(usec_t current_delay) {
        assert(current_delay <= 60 * 60 * USEC_PER_SEC);

        if (current_delay == 0)
                return USEC_PER_SEC;

        return current_delay < 60 * 60 / 2 * USEC_PER_SEC ? current_delay * 2 : 60 * 60 * USEC_PER_SEC;
}

/* RFC 6762 section 5.2
 * The querier should plan to issue a query at 80% of
 * the record lifetime, and then if no answer is received, at 85%, 90%, and 95%. */
static inline int DNS_RECORD_TTL_STATE_TO_PERCENT(DnsRecordTTLState ttl_state) {
        static const int ttl_percent_table[_DNS_RECORD_TTL_STATE_MAX] = {
                [DNS_RECORD_TTL_STATE_80_PERCENT]  = 80,
                [DNS_RECORD_TTL_STATE_85_PERCENT]  = 85,
                [DNS_RECORD_TTL_STATE_90_PERCENT]  = 90,
                [DNS_RECORD_TTL_STATE_95_PERCENT]  = 95,
                [DNS_RECORD_TTL_STATE_100_PERCENT] = 100,
        };
        if (ttl_state < 0 || ttl_state >= _DNS_RECORD_TTL_STATE_MAX)
                return -EINVAL;
        return ttl_percent_table[ttl_state];
}

static usec_t mdns_maintenance_next_time(usec_t until, usec_t ttl_usec, DnsRecordTTLState ttl_state) {
        assert(ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT);
        assert(ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        int percent = DNS_RECORD_TTL_STATE_TO_PERCENT(ttl_state);
        assert(percent > 0);
        assert(percent <= 100);

        return usec_sub_unsigned(until, (100 - percent) * ttl_usec / 100);
}

/* RFC 6762 section 5.2
 * A random variation of 2% of the record TTL should
 * be added to maintenance queries. */
static usec_t mdns_maintenance_jitter(usec_t ttl_usec) {
        /* A zero TTL (as seen on the wire for goodbyes, or substituted for out-of-range TTLs per RFC
         * 2181) must yield zero jitter: random_u64_range() treats 0 as "the full 64-bit range", which
         * would saturate the maintenance timer to never-fire. */
        if (ttl_usec == 0)
                return 0;

        return random_u64_range(2 * ttl_usec / 100);
}

static void mdns_querier_schedule_maintenance(DnsServiceQuerier *sq);

static DnssdDiscoveredService *dnssd_discovered_service_free(DnssdDiscoveredService *service);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdDiscoveredService *, dnssd_discovered_service_free);

/* Revisit both families: the ladder is armed against the soonest expiry across both, and the callee
 * logs about failures itself. */
static void mdns_querier_revisit_cache_both(DnsServiceQuerier *sq) {
        int af;

        assert(sq);

        FOREACH_ARGUMENT(af, AF_INET, AF_INET6)
                (void) mdns_querier_revisit_cache(sq, af);
}

static void mdns_querier_query_complete(DnsQuery *q) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = q;

        assert(query);
        assert(query->manager);

        sq = dns_service_querier_ref(query->service_querier_request);
        if (!sq)
                return;

        if (query->state != DNS_TRANSACTION_SUCCESS)
                return;

        mdns_querier_revisit_cache_both(sq);
}

/* A maintenance query in flight pins the querier via its reference; abort it when the last
 * subscriber is gone, so the querier can be released. (Freeing the query clears the tracking field,
 * whichever way the query goes away — see dns_query_free().) */
static void mdns_querier_abort_maintenance_query(DnsServiceQuerier *sq) {
        assert(sq);

        if (!sq->maintenance_query)
                return;

        dns_query_complete(sq->maintenance_query, DNS_TRANSACTION_ABORTED);
}

/* Fire the querier's browse question on the wire once; the answers flow back through the regular
 * completion revisit. At most one such query in flight per querier: one that has not completed by
 * the time the next is due is superseded. */
static int mdns_querier_send_question(DnsServiceQuerier *sq, bool cache_ok) {
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        int r;

        assert(sq);

        mdns_querier_abort_maintenance_query(sq);

        /* sq->flags itself stays untouched: it is part of the querier's identity. */
        r = dns_query_new(
                        sq->manager,
                        &q,
                        sq->question_utf8,
                        sq->question_idna,
                        /* question_bypass= */ NULL,
                        sq->ifindex,
                        sq->flags | SD_RESOLVED_QUERY_CONTINUOUS | (cache_ok ? 0 : SD_RESOLVED_NO_CACHE));
        if (r < 0)
                return r;

        q->complete = mdns_querier_query_complete;
        q->service_querier_request = dns_service_querier_ref(sq);

        /* Track the query before starting it: dns_query_go() completes a query synchronously when no
         * scope matches the question or the cache answers it, and the completion handler then frees
         * the query and clears this field again. A pointer stored only afterwards would dangle. */
        sq->maintenance_query = TAKE_PTR(q);

        r = dns_query_go(sq->maintenance_query);
        if (r < 0) {
                sq->maintenance_query = dns_query_free(sq->maintenance_query);
                return r;
        }

        return 0;
}

/* One re-confirmation ladder per browser: the maintenance query re-issues the
 * browse PTR question, and a single PTR response refreshes the entire browsed
 * RRset (all discovered instances). Running the RFC 6762 §5.2 80/85/90/95/100%
 * ladder once per browser — instead of once per discovered service — avoids
 * multicasting the same question N*M times when N clients browse a type with M
 * instances, while preserving loss-resilient re-confirmation and prompt
 * removal-at-expiry. */
int mdns_querier_maintenance(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        int r;

        /* Hold a ref for the duration of the handler, as mdns_next_query_schedule() does. */
        sq = dns_service_querier_ref(ASSERT_PTR(userdata));

        /* Terminal: the soonest expiry has elapsed. Reconcile the cache (this prunes expired records
         * and emits "removed") and reschedule against what remains — the revisit frees services,
         * never the querier that owns this timer. */
        if (sq->rr_ttl_state == DNS_RECORD_TTL_STATE_100_PERCENT) {
                sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
                mdns_querier_revisit_cache_both(sq);
                mdns_querier_schedule_maintenance(sq);
                return 0;
        }

        /* Advance the ladder and re-issue the browse question to re-confirm the RRset. Errors are
         * logged and swallowed: a negative return would make sd-event disable the source over the
         * re-arm, leaving the ladder dead for good. */
        sq->rr_ttl_state++;

        mdns_querier_schedule_maintenance(sq);

        r = mdns_querier_send_question(sq, /* cache_ok= */ false);
        if (r < 0)
                log_warning_errno(r, "Failed to send mDNS maintenance query, ignoring: %m");

        return 0;
}

/* (Re)arm the querier's single maintenance ladder against the soonest-expiring
 * discovered service. Disables the timer when no services remain. */
static void mdns_querier_schedule_maintenance(DnsServiceQuerier *sq) {
        DnssdDiscoveredService *soonest = NULL;
        usec_t next_time = 0;
        int r;

        assert(sq);

        LIST_FOREACH(dns_services, s, sq->dns_services)
                if (!soonest || s->until < soonest->until)
                        soonest = s;

        if (!soonest) {
                sq->maintenance_event = sd_event_source_disable_unref(sq->maintenance_event);
                return;
        }

        usec_t ttl_usec = soonest->rr->ttl * USEC_PER_SEC;
        usec_t usec = now(CLOCK_BOOTTIME);

        /* Skip ladder increments whose scheduled time already elapsed (e.g. a
         * service discovered late in its lifetime, or a lingering expired one). */
        while (sq->rr_ttl_state < _DNS_RECORD_TTL_STATE_MAX) {
                next_time = mdns_maintenance_next_time(soonest->until, ttl_usec, sq->rr_ttl_state);
                if (next_time >= usec)
                        break;

                sq->rr_ttl_state++;
        }

        if (next_time < usec) {
                /* Already at/past expiry: re-check shortly so the terminal branch
                 * prunes the record from cache and emits the removal. */
                next_time = usec_add(usec, USEC_PER_SEC);
                sq->rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;
        }

        /* The 2% jitter desynchronizes the §5.2 re-confirmation queries across queriers; the terminal
         * rung is our own expiry check, not a query — arming it past the record's actual expiry would
         * only delay the removal this ladder exists to guarantee. */
        usec_t jitter = sq->rr_ttl_state == DNS_RECORD_TTL_STATE_100_PERCENT ?
                0 : mdns_maintenance_jitter(ttl_usec);

        r = event_reset_time(
                        sq->manager->event,
                        &sq->maintenance_event,
                        CLOCK_BOOTTIME,
                        usec_add(next_time, jitter),
                        /* accuracy= */ 0,
                        mdns_querier_maintenance,
                        sq,
                        /* priority= */ 0,
                        "mdns-querier-maintenance",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to schedule mDNS maintenance query, ignoring: %m");
}

int dns_add_new_service(DnsServiceQuerier *sq, DnsResourceRecord *rr, int owner_family, int ifindex, usec_t until) {
        _cleanup_(dnssd_discovered_service_freep) DnssdDiscoveredService *s = NULL;

        assert(sq);
        assert(rr);

        s = new(DnssdDiscoveredService, 1);
        if (!s)
                return log_oom();

        *s = (DnssdDiscoveredService) {
                .rr = dns_resource_record_copy(rr),
                .family = owner_family,
                .ifindex = ifindex,
                .until = until,
        };
        if (!s->rr)
                return log_oom();

        LIST_PREPEND(dns_services, sq->dns_services, s);
        TAKE_PTR(s);

        /* The list changed: wind the ladder back (see rr_ttl_state). */
        sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
        return 0;
}

void dns_remove_service(DnsServiceQuerier *sq, DnssdDiscoveredService *service) {
        assert(sq);
        assert(service);

        LIST_REMOVE(dns_services, sq->dns_services, service);
        dnssd_discovered_service_free(service);

        /* The list changed: wind the ladder back (see rr_ttl_state). */
        sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
}

static DnssdDiscoveredService *dnssd_discovered_service_free(DnssdDiscoveredService *service) {
        if (!service)
                return NULL;

        service->rr = dns_resource_record_unref(service->rr);

        return mfree(service);
}

static void mdns_service_update(DnssdDiscoveredService *service, DnsResourceRecord *rr, usec_t until) {
        assert(service);
        assert(rr);

        service->until = until;
        service->rr->ttl = rr->ttl;
}

static int mdns_answer_item_ifindex(DnsServiceQuerier *sq, DnsAnswerItem *item) {
        assert(sq);
        assert(item);

        return item->ifindex > 0 ? item->ifindex : sq->ifindex;
}

static int dns_service_matches(
                DnssdDiscoveredService *service,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex) {

        int r;

        assert(service);
        assert(rr);

        r = dns_resource_record_equal(service->rr, rr);
        if (r <= 0)
                return r;

        return service->family == owner_family && service->ifindex == ifindex;
}

int dns_service_match_and_update(
                DnssdDiscoveredService *services,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until) {

        int r;

        /* Check if a discovered service matching the given resource record, owner family, and ifindex exists
         * in the list. If found, update the service's expiration time if the new 'until' is later, unless the
         * TTL is <= 1 (goodbye packet). Return positive if a matching service is found, zero otherwise. */

        LIST_FOREACH(dns_services, service, services) {
                r = dns_service_matches(service, rr, owner_family, ifindex);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (rr->ttl <= 1)
                        return 1;

                if (service->until < until)
                        mdns_service_update(service, rr, until);

                return 1;
        }

        return 0;
}

int mdns_answer_contains_service(
                DnsServiceQuerier *sq,
                DnsAnswer *answer,
                DnssdDiscoveredService *service) {

        DnsAnswerItem *item;
        int r;

        assert(sq);
        assert(service);

        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                r = dns_service_matches(
                                service,
                                item->rr,
                                service->family,
                                mdns_answer_item_ifindex(sq, item));
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

        return 0;
}

void dns_browse_services_purge(Manager *m, int family) {
        int r = 0;

        /* Called after caches are flushed.
         * Clear local service records and notify varlink client. */
        if (!m)
                return;

        DnsServiceQuerier *sq;
        HASHMAP_FOREACH(sq, m->dns_service_queriers) {
                r = sd_event_source_set_enabled(sq->schedule_event, SD_EVENT_OFF);
                if (r < 0)
                        log_error_errno(r, "Failed to disable event source for service querier, ignoring: %m");

                if (IN_SET(family, AF_INET, AF_UNSPEC)) {
                        r = mdns_querier_revisit_cache(sq, AF_INET);
                        if (r < 0)
                                log_error_errno(r, "Failed to revisit cache for IPv4, ignoring: %m");
                }

                if (IN_SET(family, AF_INET6, AF_UNSPEC)) {
                        r = mdns_querier_revisit_cache(sq, AF_INET6);
                        if (r < 0)
                                log_error_errno(r, "Failed to revisit cache for IPv6, ignoring: %m");
                }
        }
}

int mdns_manage_services_answer(DnsServiceQuerier *sq, DnsAnswer *answer, int owner_family) {
        DnsAnswerItem *item;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(sq);

        /* Check for new service added */
        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                int ifindex = mdns_answer_item_ifindex(sq, item);

                r = dns_service_match_and_update(sq->dns_services, item->rr, owner_family, ifindex, item->until);
                if (r < 0) {
                        log_error_errno(r, "Failed to match DNS service: %m");
                        goto finish;
                }
                if (r > 0) {
                        /* Seen again: wind the ladder back (see rr_ttl_state). */
                        sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
                        continue;
                }

                r = browse_service_update_append(&array, item->rr, owner_family, ifindex, BROWSE_SERVICE_UPDATE_ADDED);
                if (r < 0) {
                        log_error_errno(r, "Failed to append 'added' service event: %m");
                        goto finish;
                }
                if (r == 0)
                        continue;

                r = dns_add_new_service(sq, item->rr, owner_family, ifindex, item->until);
                if (r < 0) {
                        log_error_errno(r, "Failed to add new DNS service: %m");
                        goto finish;
                }
        }

        /* Check for services removed */
        LIST_FOREACH(dns_services, service, sq->dns_services) {
                if (service->family != owner_family)
                        continue;

                r = mdns_answer_contains_service(sq, answer, service);
                if (r < 0) {
                        log_error_errno(r, "Failed to match DNS answer against service list: %m");
                        goto finish;
                }
                if (r > 0)
                        continue;

                r = browse_service_update_append(&array, service->rr, owner_family, service->ifindex, BROWSE_SERVICE_UPDATE_REMOVED);
                if (r < 0) {
                        log_error_errno(r, "Failed to append 'removed' service event: %m");
                        goto finish;
                }

                dns_remove_service(sq, service);
        }

        /* (Re-)arm the querier's maintenance ladder once against the reconciled list — doing it per
         * added/removed instance inside the loops above would make reconciling an answer with M
         * instances O(M²), with M driven by untrusted multicast input. This also disables the timer
         * when no discovered service remains. */
        mdns_querier_schedule_maintenance(sq);

        if (!sd_json_variant_is_blank_array(array)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *vm = NULL;

                r = sd_json_buildo(&vm, SD_JSON_BUILD_PAIR_VARIANT("browserServiceData", array));
                if (r < 0) {
                        log_error_errno(r,
                                        "Failed to build JSON object for browser service data: %m");
                        goto finish;
                }

                /* Deliver the same update to every subscriber of this querier. A failure to notify
                 * one of them must not keep the others from being served — but the affected
                 * subscriber cannot stay on a diff-only stream that just lost a batch: end its
                 * subscription with an error, so it knows to resubscribe for a fresh snapshot. */
                LIST_FOREACH(subscribers, sb, sq->subscribers) {
                        r = sd_varlink_notify(sb->link, vm);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to notify a browse subscriber via varlink, dropping its subscription: %m");
                                (void) sd_varlink_error_errno(sb->link, r);
                        }
                }
        }

        return 0;

finish:
        /* The events accumulated for this batch are lost with the failure. Terminate every
         * subscription with an error instead of carrying on silently -- an errored-out client knows
         * to resubscribe and is then served a fresh snapshot, while a silently dropped batch would
         * leave its view stale with no signal that anything is missing. */
        LIST_FOREACH(subscribers, sb, sq->subscribers)
                (void) sd_varlink_error_errno(sb->link, r);

        return r;
}

int mdns_querier_revisit_cache(DnsServiceQuerier *sq, int owner_family) {
        int r;

        assert(sq);
        assert(sq->manager);

        /* The reconciliation must see real cache expiry times: without SD_RESOLVED_NO_STALE the
         * lookup substitutes the stale-serving clamp for item->until — an absolute timestamp ~30s
         * after boot, i.e. long in the past on any running system — which would wedge the
         * maintenance ladder in its past-expiry one-second re-check for as long as a matching
         * record stays cached. Stale serving is a per-client query feature; the browse
         * bookkeeping always wants the truth, whatever flags the subscriber passed. */
        uint64_t lookup_flags = sq->flags | SD_RESOLVED_NO_STALE;

        /* ifindex=0 means "all interfaces"; with a specific ifindex the loop below degenerates to
         * the one matching scope. Collect the cached answers from every matching mDNS scope into a
         * single combined answer and reconcile once. Reconciling per-scope would be wrong:
         * mdns_manage_services_answer() derives removals by diffing the querier's global service
         * list against the answer it is handed, so a single scope's answer would spuriously
         * "remove" (and then, on the next scope/pass, re-"add") services that are still present on
         * other interfaces — resulting in a continuous added/removed event flap for services seen
         * on more than the current scope. With no matching scope at all (mDNS is off on the link,
         * or the link is gone) the reconcile runs against an empty answer: lingering instances get
         * their removed events and the ladder winds down, instead of re-checking a list nothing
         * can update once per second. */
        _cleanup_(dns_answer_unrefp) DnsAnswer *combined = NULL;

        LIST_FOREACH(scopes, scope, sq->manager->dns_scopes) {
                _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
                DnsAnswerItem *item;

                if (scope->protocol != DNS_PROTOCOL_MDNS)
                        continue;

                if (scope->family != owner_family)
                        continue;

                if (sq->ifindex != 0 && dns_scope_ifindex(scope) != sq->ifindex)
                        continue;

                dns_cache_prune(&scope->cache);

                r = dns_cache_lookup(
                                &scope->cache,
                                sq->key,
                                lookup_flags,
                                /* ret_rcode= */ NULL,
                                &answer,
                                /* ret_full_packet= */ NULL,
                                /* ret_query_flags= */ NULL,
                                /* ret_dnssec_result= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to look up DNS cache for service browser key on scope %s: %m",
                                               dns_scope_ifname(scope) ?: "global");

                /* Merge preserving each item's ifindex, flags, rrsig and
                 * cache-expiry 'until'. (dns_answer_extend()/merge() would
                 * reset 'until' to USEC_INFINITY, which would skew the RFC
                 * 6762 §5.2 TTL-maintenance schedule that
                 * mdns_manage_services_answer() derives from item->until.) */
                DNS_ANSWER_FOREACH_ITEM(item, answer) {
                        r = dns_answer_add_extend_full(&combined, item->rr, item->ifindex,
                                                       item->flags, item->rrsig, item->until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to merge mDNS cache answer from scope %s: %m",
                                                       dns_scope_ifname(scope) ?: "global");
                }
        }

        r = mdns_manage_services_answer(sq, combined, owner_family);
        if (r < 0)
                return log_error_errno(r, "Failed to manage mDNS services after cache lookup: %m");

        return 0;
}

int mdns_queriers_notify_goodbye(DnsScope *scope) {
        DnsServiceQuerier *sq;
        int r;

        if (!scope)
                return 0;

        /* A goodbye-driven removal is a one-shot event: keep going when one querier's revisit
         * fails, or every querier behind it in hash order would silently miss this round. */
        HASHMAP_FOREACH(sq, scope->manager->dns_service_queriers) {
                r = mdns_querier_revisit_cache(sq, scope->family);
                if (r < 0)
                        log_warning_errno(r,
                                          "Failed to revisit cache for service querier with family %d, ignoring: %m",
                                          scope->family);
        }

        return 0;
}

/* RFC 6762 §10.1 defers acting on a goodbye by one second so that other
 * publishers of the same records can rescue them. resolved keeps a single
 * cache entry per record, whatever machine announced it, so without a nudge
 * that rescue only happens by luck: a surviving publisher of the same
 * instance re-announces on its own schedule, and the browse question's §5.2
 * backoff can be a full hour away — until then the subscriber sees a spurious
 * 'removed' for a service that never went away. Re-issue the browse question
 * as soon as a goodbye matches it: a surviving publisher's answer then
 * refreshes the record inside the one-second grace and no removal is ever
 * reported. If nobody answers, the goodbye takes effect exactly as before. */
void mdns_queriers_rescue_query_goodbye(DnsScope *scope, DnsAnswer *answer) {
        DnsServiceQuerier *sq;
        DnsResourceRecord *rr;
        usec_t t;
        int r;

        assert(scope);
        assert(scope->manager);

        t = now(CLOCK_BOOTTIME);

        HASHMAP_FOREACH(sq, scope->manager->dns_service_queriers) {
                bool match = false;

                if (sq->ifindex != 0 && sq->ifindex != dns_scope_ifindex(scope))
                        continue;

                /* Half the §10.1 grace: covers goodbye repetitions at their
                 * usual one-second spacing, and bounds the query rate should
                 * someone flood us with goodbyes. */
                if (sq->last_goodbye_rescue_usec > 0 &&
                    t < usec_add(sq->last_goodbye_rescue_usec, USEC_PER_SEC / 2))
                        continue;

                DNS_ANSWER_FOREACH(rr, answer) {
                        /* Goodbyes arrive here with their TTL already rewritten to 1. */
                        if (rr->ttl > 1)
                                continue;

                        if (dns_resource_key_equal(rr->key, sq->key) > 0) {
                                match = true;
                                break;
                        }
                }
                if (!match)
                        continue;

                sq->last_goodbye_rescue_usec = t;

                r = mdns_querier_send_question(sq, /* cache_ok= */ false);
                if (r < 0)
                        log_warning_errno(r, "Failed to send mDNS rescue query for a goodbye, ignoring: %m");
        }
}

int mdns_queriers_notify_unsolicited_updates(Manager *m, DnsAnswer *answer, int owner_family) {
        DnsServiceQuerier *sq;
        int r;

        assert(m);

        if (!answer)
                return 0;

        HASHMAP_FOREACH(sq, m->dns_service_queriers) {

                r = dns_answer_match_key(answer, sq->key, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to match answer key with service querier's key, ignoring: %m");
                        continue;
                }
                if (r == 0)
                        continue;

                r = mdns_querier_revisit_cache(sq, owner_family);
                if (r < 0)
                        log_warning_errno(r, "Failed to revisit cache for service querier, ignoring: %m");
        }

        return 0;
}

static int mdns_next_query_schedule(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        bool first;
        int r;

        assert(userdata);
        assert_se(sq = dns_service_querier_ref(userdata));

        /* Re-arm before issuing anything: a negative return from the handler would make sd-event
         * disable the source, silently ending the continuous query for every subscriber sharing
         * this querier — with late joiners then attaching to a dead querier. A transient failure
         * below must cost one interval, not the subscription. */
        first = sq->delay == 0;
        sq->delay = mdns_calculate_next_query_delay(sq->delay);

        r = event_reset_time_relative(
                        sq->manager->event,
                        &sq->schedule_event,
                        CLOCK_BOOTTIME,
                        sq->delay,
                        /* accuracy= */ 0,
                        mdns_next_query_schedule,
                        sq,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to schedule next continuous browse query, ignoring: %m");

        /* RFC 6762 Section 5.2 outlines timing requirements for continuous queries. Only the very
         * first query may be served from the cache; every later one exists to poke the network. */
        r = mdns_querier_send_question(sq, /* cache_ok= */ first);
        if (r < 0)
                log_warning_errno(r, "Failed to send continuous browse query, ignoring: %m");

        return 0;
}

void dns_browse_services_restart(Manager *m) {
        int r;

        if (!(m && m->dns_service_queriers))
                return;

        DnsServiceQuerier *sq;

        HASHMAP_FOREACH(sq, m->dns_service_queriers) {
                sq->delay = 0;

                r = event_reset_time_relative(
                                sq->manager->event,
                                &sq->schedule_event,
                                CLOCK_BOOTTIME,
                                (sq->delay * USEC_PER_SEC),
                                /* accuracy= */ 0,
                                mdns_next_query_schedule,
                                sq,
                                /* priority= */ 0,
                                "mdns-next-query-schedule",
                                /* force_reset= */ true);

                if (r < 0)
                        log_error_errno(r,
                                        "Failed to reset mDNS service subscriber event for service querier: %m");
        }
}

static void dns_service_querier_hash_func(const DnsServiceQuerier *sq, struct siphash *state) {
        assert(sq);

        dns_resource_key_hash_func(sq->key, state);
        siphash24_compress_typesafe(sq->ifindex, state);
        siphash24_compress_typesafe(sq->flags, state);
}

static int dns_service_querier_compare_func(const DnsServiceQuerier *a, const DnsServiceQuerier *b) {
        int r;

        assert(a);
        assert(b);

        r = dns_resource_key_compare_func(a->key, b->key);
        if (r != 0)
                return r;

        r = CMP(a->ifindex, b->ifindex);
        if (r != 0)
                return r;

        return CMP(a->flags, b->flags);
}

DEFINE_PRIVATE_HASH_OPS(
                dns_service_querier_hash_ops,
                DnsServiceQuerier,
                dns_service_querier_hash_func,
                dns_service_querier_compare_func);

/* Bring a subscriber that joined an already-running querier up to speed: synthesize "added" events
 * for everything discovered so far, mirroring what a first cache-served query would have yielded. */
static int dns_service_browser_send_snapshot(DnsServiceBrowser *sb) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL, *vm = NULL;
        int r;

        assert(sb);
        assert(sb->querier);

        LIST_FOREACH(dns_services, service, sb->querier->dns_services) {
                r = browse_service_update_append(&array, service->rr, service->family, service->ifindex, BROWSE_SERVICE_UPDATE_ADDED);
                if (r < 0)
                        return r;
        }

        if (sd_json_variant_is_blank_array(array))
                return 0;

        r = sd_json_buildo(&vm, SD_JSON_BUILD_PAIR_VARIANT("browserServiceData", array));
        if (r < 0)
                return r;

        return sd_varlink_notify(sb->link, vm);
}

static int dns_service_querier_new(
                Manager *m,
                DnsQuestion *question_utf8,
                DnsQuestion *question_idna,
                int ifindex,
                uint64_t flags,
                DnsServiceQuerier **ret) {

        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        int r;

        assert(m);
        assert(question_utf8);
        assert(question_idna);
        assert(ret);

        sq = new(DnsServiceQuerier, 1);
        if (!sq)
                return log_oom();

        *sq = (DnsServiceQuerier) {
                .n_ref = 1,
                .manager = m,
                .question_utf8 = dns_question_ref(question_utf8),
                .question_idna = dns_question_ref(question_idna),
                .key = dns_resource_key_ref(dns_question_first_key(question_utf8)),
                .ifindex = ifindex,
                .flags = flags,
                .delay = 0,
        };

        r = sd_event_add_time_relative(
                        m->event,
                        &sq->schedule_event,
                        CLOCK_BOOTTIME,
                        sq->delay,
                        /* accuracy= */ 0,
                        mdns_next_query_schedule,
                        sq);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(sq);
        return 0;
}

/* Detach a subscriber. The last one takes the querier off the air: it is dropped from the manager's
 * registry and its timers are disabled right away, so no further queries hit the wire while in-flight
 * completions (which hold their own reference) wind down against an empty subscriber list. */
static void dns_service_querier_detach(DnsServiceQuerier *sq, DnsServiceBrowser *sb) {
        assert(sq);
        assert(sb);

        LIST_REMOVE(subscribers, sq->subscribers, sb);

        if (sq->subscribers)
                return;

        hashmap_remove(sq->manager->dns_service_queriers, sq);
        sq->schedule_event = sd_event_source_disable_unref(sq->schedule_event);
        sq->maintenance_event = sd_event_source_disable_unref(sq->maintenance_event);

        /* An in-flight maintenance query holds a reference that would keep the orphaned querier
         * alive until the query completed on its own. */
        mdns_querier_abort_maintenance_query(sq);
}

int dns_subscribe_browse_service(
                Manager *m, sd_varlink *link, const char *domain, const char *type, int ifindex, uint64_t flags) {

        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        _cleanup_(dns_service_browser_freep) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        int r;

        assert(m);
        assert(link);

        /* Refuse multiple requests. */
        if (hashmap_contains(m->dns_service_browsers, link))
                return -EBUSY;

        if (ifindex < 0)
                return sd_varlink_error_invalid_parameter_name(link, "ifindex");

        if (ifindex == 0)
                log_debug("BrowseServices: browsing all mDNS interfaces");

        if (isempty(type))
                type = NULL;
        else if (!dnssd_srv_type_is_valid(type))
                return sd_varlink_error_invalid_parameter_name(link, "type");

        if (isempty(domain))
                domain = "local";
        else {
                r = dns_name_is_valid(domain);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_varlink_error_invalid_parameter_name(link, "domain");
        }

        /* Only mDNS continuous querying is currently supported. See RFC 6762 */
        if (!FLAGS_SET(flags, SD_RESOLVED_MDNS))
                return -EINVAL;

        r = dns_question_new_service_pointer(
                        &question_utf8, type, domain, /* convert_idna= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to create DNS question for UTF8 version: %m");

        r = dns_question_new_service_pointer(
                        &question_idna, type, domain, /* convert_idna= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to create DNS question for IDNA version: %m");

        /* One querier per browse question: if somebody is asking this already, join them instead of
         * multicasting the same question a second time. */
        DnsServiceQuerier *shared = hashmap_get(
                        m->dns_service_queriers,
                        &(DnsServiceQuerier) {
                                .key = dns_question_first_key(question_utf8),
                                .ifindex = ifindex,
                                .flags = flags,
                        });
        if (shared)
                sq = dns_service_querier_ref(shared);
        else {
                r = dns_service_querier_new(m, question_utf8, question_idna, ifindex, flags, &sq);
                if (r < 0)
                        return r;
        }

        /* Subscribe first, register afterwards: any failure from here on unwinds through
         * dns_service_browser_free() -> dns_service_querier_detach(), whose registry removal is a
         * no-op for a querier that was never inserted. */
        sb = new(DnsServiceBrowser, 1);
        if (!sb)
                return log_oom();

        *sb = (DnsServiceBrowser) {
                .link = sd_varlink_ref(link),
                .querier = dns_service_querier_ref(sq),
        };

        LIST_PREPEND(subscribers, sq->subscribers, sb);

        if (!shared) {
                r = hashmap_ensure_put(&m->dns_service_queriers, &dns_service_querier_hash_ops, sq, sq);
                if (r < 0)
                        return log_error_errno(r, "Failed to add service querier to the hashmap: %m");
        }

        r = hashmap_ensure_put(&m->dns_service_browsers, NULL, link, sb);
        if (r < 0)
                return log_error_errno(r, "Failed to add service browser to the hashmap: %m");

        /* A late joiner inherits the querier's current view; hand it over right away. Everything
         * after this arrives as regular diff events like for any other subscriber. A subscriber
         * whose snapshot failed must not stay registered with a silently empty view — fail the
         * call instead, so the client knows to resubscribe. This matches the policy at
         * mdns_manage_services_answer()'s finish: label for lost diff batches. */
        if (shared) {
                r = dns_service_browser_send_snapshot(sb);
                if (r < 0) {
                        hashmap_remove(m->dns_service_browsers, link);
                        return log_debug_errno(r, "Failed to send initial browse snapshot: %m");
                }
        }

        TAKE_PTR(sb);

        return 0;
}

/* The counterpart of dns_subscribe_browse_service(): drop the browser registered for a varlink
 * connection. Freeing it detaches it from its querier, which is torn down — a maintenance query still
 * in flight included — once its last subscriber is gone. */
void dns_unsubscribe_browse_service(Manager *m, sd_varlink *link) {
        assert(m);
        assert(link);

        dns_service_browser_free(hashmap_remove(m->dns_service_browsers, link));
}

DnsServiceBrowser *dns_service_browser_free(DnsServiceBrowser *sb) {
        if (!sb)
                return NULL;

        if (sb->querier) {
                dns_service_querier_detach(sb->querier, sb);
                sb->querier = dns_service_querier_unref(sb->querier);
        }

        sb->link = sd_varlink_unref(sb->link);

        return mfree(sb);
}

static DnsServiceQuerier *dns_service_querier_free(DnsServiceQuerier *sq) {
        if (!sq)
                return NULL;

        assert(!sq->subscribers);

        while (sq->dns_services)
                dns_remove_service(sq, sq->dns_services);

        sq->schedule_event = sd_event_source_disable_unref(sq->schedule_event);
        sq->maintenance_event = sd_event_source_disable_unref(sq->maintenance_event);

        sq->question_idna = dns_question_unref(sq->question_idna);
        sq->question_utf8 = dns_question_unref(sq->question_utf8);
        sq->key = dns_resource_key_unref(sq->key);

        return mfree(sq);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsServiceQuerier, dns_service_querier, dns_service_querier_free);
