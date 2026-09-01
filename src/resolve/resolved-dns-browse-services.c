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

/* One per varlink BrowseServices subscription; just the client's connection plus its seat on the
 * shared querier. Private to this file: nothing outside it holds a browser, they are reached
 * through the manager's map or the querier's subscriber list. */
struct DnsServiceBrowser {
        sd_varlink *link;
        DnsServiceQuerier *querier;
        LIST_FIELDS(DnsServiceBrowser, subscribers);
};

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

/* Wrap one batch of browse events in the varlink notification envelope and send it to a single
 * subscriber. */
static int browse_service_notify(sd_varlink *link, sd_json_variant *array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vm = NULL;
        int r;

        assert(link);

        if (sd_json_variant_is_blank_array(array))
                return 0;

        r = sd_json_buildo(&vm, SD_JSON_BUILD_PAIR_VARIANT("browserServiceData", array));
        if (r < 0)
                return r;

        return sd_varlink_notify(link, vm);
}

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

        /* Every field is emitted unconditionally: type and domain are non-nullable in the varlink
         * IDL, and while name is nullable, added and removed events must carry identical keys for
         * a consumer to pair them — an instance-less type enumeration (RFC 6763 §9) is reported
         * with an empty name rather than none. */
        r = sd_json_buildo(
                        &entry,
                        SD_JSON_BUILD_PAIR_STRING(
                                        "updateFlag",
                                        browse_service_update_event_to_string(event)),
                        SD_JSON_BUILD_PAIR_INTEGER("family", family),
                        SD_JSON_BUILD_PAIR_STRING("name", strempty(name)),
                        SD_JSON_BUILD_PAIR_STRING("type", type),
                        SD_JSON_BUILD_PAIR_STRING("domain", strempty(domain)),
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

static usec_t mdns_maintenance_next_time(usec_t until, usec_t span, DnsRecordTTLState ttl_state) {
        assert(ttl_state >= DNS_RECORD_TTL_STATE_80_PERCENT);
        assert(ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        int percent = DNS_RECORD_TTL_STATE_TO_PERCENT(ttl_state);
        assert(percent > 0);
        assert(percent <= 100);

        return usec_sub_unsigned(until, (100 - percent) * span / 100);
}

/* The lifetime the ladder spreads its rungs over. Not the wire TTL: that is an unclamped 32-bit
 * value chosen by whoever announced the record, while the anchor the rungs are measured back from is
 * the cache's expiry, which calculate_until_valid() caps at CACHE_TTL_MAX_USEC. Mixing the two puts
 * every rung of a long-TTL record in the past -- one peer announcing a PTR with a multi-hour TTL
 * would otherwise switch the RFC 6762 §5.2 re-confirmation off for every instance the querier
 * holds, since the ladder is shared per browse question. */
static usec_t mdns_maintenance_span(DnsResourceRecord *rr) {
        assert(rr);

        return MIN(rr->ttl * USEC_PER_SEC, CACHE_TTL_MAX_USEC);
}

/* The discovered service whose cache entry expires first: the one the shared ladder tracks. */
static DnssdDiscoveredService* mdns_querier_soonest_service(DnsServiceQuerier *sq) {
        DnssdDiscoveredService *soonest = NULL;

        assert(sq);

        LIST_FOREACH(dns_services, s, sq->dns_services)
                if (!soonest || s->until < soonest->until)
                        soonest = s;

        return soonest;
}

/* The rungs sit 5% of the span apart. RFC 6762 §5.2 also requires at least a second between
 * successive queries for the same question, so when 5% of the span is under a second the
 * intermediate rungs would fire four multicasts of one question inside a few hundred milliseconds --
 * a TTL of 2 puts them 100ms apart. Collapse the ladder to a single re-confirmation at 80% plus the
 * terminal expiry check in that case: the terminal rung is our own cache check rather than a query,
 * so one query rung leaves no interval to violate. */
static DnsRecordTTLState mdns_maintenance_next_state(usec_t span, DnsRecordTTLState ttl_state) {
        assert(ttl_state < _DNS_RECORD_TTL_STATE_MAX);

        if (span / 20 < USEC_PER_SEC && ttl_state < DNS_RECORD_TTL_STATE_100_PERCENT)
                return DNS_RECORD_TTL_STATE_100_PERCENT;

        return ttl_state + 1;
}

/* RFC 6762 section 5.2
 * A random variation of 2% of the record TTL should
 * be added to maintenance queries. */
static usec_t mdns_maintenance_jitter(usec_t span) {
        /* A zero TTL (as seen on the wire for goodbyes, or substituted for out-of-range TTLs per RFC
         * 2181) must yield zero jitter: random_u64_range() treats 0 as "the full 64-bit range", which
         * would saturate the maintenance timer to never-fire. */
        if (span == 0)
                return 0;

        return random_u64_range(2 * span / 100);
}

static DnsServiceBrowser* dns_service_browser_free(DnsServiceBrowser *sb);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnsServiceBrowser *, dns_service_browser_free);

static void mdns_querier_schedule_maintenance(DnsServiceQuerier *sq);
static int mdns_querier_revisit_cache(DnsServiceQuerier *sq, int owner_family);

static DnssdDiscoveredService* dnssd_discovered_service_free(DnssdDiscoveredService *service);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdDiscoveredService *, dnssd_discovered_service_free);

/* Revisit one family's cache -- or both, for AF_UNSPEC: the ladder is armed against the soonest
 * expiry across both. The one place a failed revisit is reported and swallowed, whichever caller
 * reached it. */
static void mdns_querier_revisit_cache_family(DnsServiceQuerier *sq, int family) {
        int af, r;

        assert(sq);

        FOREACH_ARGUMENT(af, AF_INET, AF_INET6) {
                if (family != AF_UNSPEC && family != af)
                        continue;

                r = mdns_querier_revisit_cache(sq, af);
                if (r < 0)
                        log_warning_errno(r, "Failed to revisit cache for %s, ignoring: %m",
                                          af_to_ipv4_ipv6(af));
        }
}

static void mdns_querier_query_complete(DnsQuery *q) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        _cleanup_(dns_query_freep) DnsQuery *query = q;

        assert(query);
        assert(query->manager);

        sq = dns_service_querier_ref(ASSERT_PTR(query->service_querier_request));

        if (query->state != DNS_TRANSACTION_SUCCESS)
                return;

        mdns_querier_revisit_cache_family(sq, AF_UNSPEC);
}

/* A maintenance query in flight pins the querier via its reference; abort it when the last
 * subscriber is gone, so the querier can be released. (Freeing the query clears the tracking field,
 * whichever way the query goes away — see dns_query_free().) */
static void mdns_querier_abort_query(DnsServiceQuerier *sq) {
        assert(sq);

        if (!sq->in_flight_query)
                return;

        /* The completion handler may be running right now — a notify failure inside it can tear
         * down the last subscriber and land here with the query already completed. Completing it
         * again would assert (or re-enter the handler); dns_query_free() clears the tracking field
         * once the handler returns. */
        if (!DNS_TRANSACTION_IS_LIVE(sq->in_flight_query->state))
                return;

        dns_query_complete(sq->in_flight_query, DNS_TRANSACTION_ABORTED);
}

/* Let the querier forget a query that is going away, whichever path it dies on, so its tracking
 * pointer can never dangle. Called by the query layer, which does not know how the querier tracks
 * it; tolerates a NULL querier so the caller needs no guard of its own. */
void dns_service_querier_forget_query(DnsServiceQuerier *sq, DnsQuery *q) {
        assert(q);

        if (sq && sq->in_flight_query == q)
                sq->in_flight_query = NULL;
}

/* Fire the querier's browse question on the wire once; the answers flow back through the regular
 * completion revisit. At most one such query in flight per querier: one that has not completed by
 * the time the next is due is superseded. */
static int mdns_querier_send_question(DnsServiceQuerier *sq, bool cache_ok) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin = NULL;
        _cleanup_(dns_query_freep) DnsQuery *q = NULL;
        int r;

        /* Pinned here rather than left to the callers: both the abort below and dns_query_go() can
         * run a completion handler that drops the last subscriber, and this function keeps using sq
         * afterwards. Every caller happens to pin today; this makes that not a thing to remember. */
        pin = dns_service_querier_ref(ASSERT_PTR(sq));

        mdns_querier_abort_query(sq);

        /* sq->flags itself stays untouched: it is part of the querier's identity. With cache_ok the
         * query may be answered from the cache — that is how a fresh querier serves its first
         * subscriber instantly; without it the query exists to poke the network. */
        r = dns_query_new(
                        sq->manager,
                        &q,
                        sq->question_utf8,
                        sq->question_idna,
                        /* question_bypass= */ NULL,
                        sq->ifindex,
                        sq->flags |
                        SD_RESOLVED_QUERY_CONTINUOUS |
                        (cache_ok ? 0 : SD_RESOLVED_NO_CACHE));
        if (r < 0)
                return r;

        q->complete = mdns_querier_query_complete;
        q->service_querier_request = dns_service_querier_ref(sq);

        /* Track the query before starting it: dns_query_go() completes a query synchronously when no
         * scope matches the question or the cache answers it, and the completion handler then frees
         * the query and clears this field again. A pointer stored only afterwards would dangle. */
        sq->in_flight_query = TAKE_PTR(q);

        r = dns_query_go(sq->in_flight_query);
        if (r < 0) {
                sq->in_flight_query = dns_query_free(sq->in_flight_query);
                return r;
        }

        /* Every emitter -- the ladder, the continuous schedule, the goodbye rescue and a joining
         * subscriber's catch-up -- comes through here, so this is where the question's last wire
         * time belongs. Two things must not stamp it: a cache hit, which completes inside
         * dns_query_go() and clears this field, and a query a resolver hook deferred, which stays
         * alive at DNS_TRANSACTION_NULL with nothing sent. Either would make the next emitter skip
         * on a packet that never went out. */
        if (sq->in_flight_query && sq->in_flight_query->state != DNS_TRANSACTION_NULL)
                sq->last_wire_query_usec = now(CLOCK_BOOTTIME);

        return 0;
}

/* RFC 6762 §5.2: successive queries for one question are at least a second apart. The floor is a
 * property of the question, so every emitter asks before adding to the wire -- the ladder, the
 * continuous schedule, the goodbye rescue and a joining subscriber's catch-up. Nothing is lost by
 * skipping a query in that window: the one already in flight is the same question on the same
 * scopes, so an answer to it refreshes the record well inside the §10.1 grace. */
static bool mdns_querier_may_query_now(DnsServiceQuerier *sq, usec_t t) {
        assert(sq);

        return sq->last_wire_query_usec == 0 ||
                t >= usec_add(sq->last_wire_query_usec, USEC_PER_SEC);
}

/* One re-confirmation ladder per querier: the maintenance query re-issues the
 * browse PTR question, and a single PTR response refreshes the entire browsed
 * RRset (all discovered instances). Running the RFC 6762 §5.2 80/85/90/95/100%
 * ladder once per shared querier — instead of once per discovered service or
 * per client — avoids multicasting the same question N*M times when N clients
 * browse a type with M instances, while preserving loss-resilient
 * re-confirmation and prompt removal-at-expiry. */
void mdns_querier_run_maintenance(DnsServiceQuerier *sq) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin = NULL;
        int r;

        /* Hold a ref for the duration of the run, as on_mdns_querier_next_query() does. */
        pin = dns_service_querier_ref(ASSERT_PTR(sq));

        /* Terminal: the soonest expiry has elapsed. Reconcile the cache (this prunes expired records
         * and emits "removed") and reschedule against what remains — the revisit frees services,
         * never the querier that owns this timer. */
        if (sq->rr_ttl_state == DNS_RECORD_TTL_STATE_100_PERCENT) {
                sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
                mdns_querier_revisit_cache_family(sq, AF_UNSPEC);

                /* Each reconciled family re-armed the ladder already; this covers the family whose
                 * revisit could not reconcile at all (a failed cache lookup), so a transient error
                 * cannot leave the ladder dead with services still listed. Skipped for a querier
                 * with no subscribers left: the reconciliation above may have dropped the last one,
                 * and re-arming a timer for a querier the caller's pin is about to free would only
                 * be undone by the free. */
                if (sq->subscribers)
                        mdns_querier_schedule_maintenance(sq);

                return;
        }

        /* Advance the ladder and re-issue the browse question to re-confirm the RRset. Errors are
         * logged and swallowed: a negative return would make sd-event disable the source over the
         * re-arm, leaving the ladder dead for good. */
        DnssdDiscoveredService *soonest = mdns_querier_soonest_service(sq);
        sq->rr_ttl_state = soonest ?
                mdns_maintenance_next_state(mdns_maintenance_span(soonest->rr), sq->rr_ttl_state) :
                sq->rr_ttl_state + 1;

        mdns_querier_schedule_maintenance(sq);

        /* The §5.2 floor. This rung and the continuous schedule run off independent clocks -- one
         * derived from a record's expiry, the other from the doubling backoff -- so they can land
         * within a second of each other. The rung asks for a re-confirmation of the RRset, which is
         * exactly what the query that just went out will bring back, so skipping is not a lost
         * rung; the ladder has already advanced and re-armed above either way. */
        if (!mdns_querier_may_query_now(sq, now(CLOCK_BOOTTIME))) {
                log_debug("Browse question was just asked, skipping the maintenance query.");
                return;
        }

        r = mdns_querier_send_question(sq, /* cache_ok= */ false);
        if (r < 0)
                log_warning_errno(r, "Failed to send mDNS maintenance query, ignoring: %m");
}

static int on_mdns_querier_maintenance(sd_event_source *s, uint64_t usec, void *userdata) {
        mdns_querier_run_maintenance(userdata);
        return 0;
}

/* (Re)arm the querier's single maintenance ladder against the soonest-expiring
 * discovered service. Disables the timer when no services remain. */
static void mdns_querier_schedule_maintenance(DnsServiceQuerier *sq) {
        DnssdDiscoveredService *soonest;
        usec_t next_time = 0;
        int r;

        assert(sq);

        soonest = mdns_querier_soonest_service(sq);
        if (!soonest) {
                sq->maintenance_event = sd_event_source_disable_unref(sq->maintenance_event);
                return;
        }

        usec_t span = mdns_maintenance_span(soonest->rr);
        usec_t usec = now(CLOCK_BOOTTIME);

        /* Skip ladder increments whose scheduled time already elapsed (e.g. a
         * service discovered late in its lifetime, or a lingering expired one). */
        while (sq->rr_ttl_state < _DNS_RECORD_TTL_STATE_MAX) {
                next_time = mdns_maintenance_next_time(soonest->until, span, sq->rr_ttl_state);
                if (next_time >= usec)
                        break;

                sq->rr_ttl_state = mdns_maintenance_next_state(span, sq->rr_ttl_state);
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
                0 : mdns_maintenance_jitter(span);

        r = event_reset_time(
                        sq->manager->event,
                        &sq->maintenance_event,
                        CLOCK_BOOTTIME,
                        usec_add(next_time, jitter),
                        /* accuracy= */ 0,
                        on_mdns_querier_maintenance,
                        sq,
                        /* priority= */ 0,
                        "mdns-querier-maintenance",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to schedule mDNS maintenance query, ignoring: %m");
}

int dns_add_new_service(
                DnsServiceQuerier *sq,
                DnsResourceRecord *rr,
                int owner_family,
                int ifindex,
                usec_t until) {

        _cleanup_(dnssd_discovered_service_freep) DnssdDiscoveredService *s = NULL;

        assert(sq);
        assert(rr);

        /* Silent on failure, like the sibling steps of the caller's loop: the caller names the
         * context, and docs/CODING_STYLE.md wants only the innermost of a logging chain to log --
         * here that would be the half without the context. */
        s = new(DnssdDiscoveredService, 1);
        if (!s)
                return -ENOMEM;

        *s = (DnssdDiscoveredService) {
                .rr = dns_resource_record_copy(rr),
                .family = owner_family,
                .ifindex = ifindex,
                .until = until,
        };
        if (!s->rr)
                return -ENOMEM;

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

static DnssdDiscoveredService* dnssd_discovered_service_free(DnssdDiscoveredService *service) {
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

/* Does this querier read the link the caller is talking about? A querier not pinned to a link reads
 * them all, and an ifindex of zero from the caller means "every link" — the scope-driven callers pass
 * dns_scope_ifindex(), which is never zero for an mDNS scope. */
static bool dns_service_querier_covers_ifindex(DnsServiceQuerier *sq, int ifindex) {
        assert(sq);

        return ifindex <= 0 || sq->ifindex == 0 || sq->ifindex == ifindex;
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

        /* Check if a discovered service matching the given resource record, owner family and ifindex
         * exists in the list. If found, take the expiry the cache now holds for it — in either
         * direction, since a re-announcement may carry a shorter TTL than the one before and the
         * maintenance ladder is armed off this value: keeping the longer one would leave the ladder
         * waiting past the record's actual expiry, and the instance listed after the cache dropped
         * it. That holds for a short TTL just as much as a long one: a legitimate re-announcement
         * with TTL 1 arms no goodbye timer (resolved-mdns.c gates that on TTL 0), so skipping the
         * update here would leave the ladder anchored on an expiry the cache has already passed --
         * and, since the ladder is shared, push out the terminal check for every other instance of
         * the type too. Only the decision to *remove* belongs to the goodbye path. Return positive
         * if a matching service is found, zero otherwise. */

        LIST_FOREACH(dns_services, service, services) {
                r = dns_service_matches(service, rr, owner_family, ifindex);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                if (service->until != until)
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

/* The one fan-out over the querier registry: every path that reconciles queriers against a cache
 * change funnels through here, so the pinning discipline lives in one place -- the registry holds
 * no reference, and a revisit can drop the last subscriber and free the querier under the loop.
 * 'ifindex' selects the queriers (0: all), 'family' the cache side to reconcile (AF_UNSPEC: both),
 * and a non-NULL 'match' additionally restricts to queriers whose question the answer names. Kept
 * going on per-querier failures, or every querier behind the failing one in hash order would
 * silently miss the round. */
static void mdns_queriers_revisit(Manager *m, int ifindex, int family, DnsAnswer *match) {
        DnsServiceQuerier *sq;
        int r;

        assert(m);

        HASHMAP_FOREACH(sq, m->dns_service_queriers) {
                if (!dns_service_querier_covers_ifindex(sq, ifindex))
                        continue;

                if (match) {
                        r = dns_answer_match_key(match, sq->key, NULL);
                        if (r < 0) {
                                log_warning_errno(r,
                                                  "Failed to match answer key against a querier, "
                                                  "ignoring: %m");
                                continue;
                        }
                        if (r == 0)
                                continue;
                }

                _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin =
                        dns_service_querier_ref(sq);

                mdns_querier_revisit_cache_family(pin, family);
        }
}

/* Whether any browse question is being asked at all. Lets the packet path skip work that only
 * exists to feed the queriers without reaching into their registry itself. */
bool mdns_queriers_exist(Manager *m) {
        assert(m);

        return !hashmap_isempty(m->dns_service_queriers);
}

void dns_browse_services_purge(Manager *m, int family, int ifindex) {
        /* Called after cached records went away — all caches flushed, one scope (and its cache) on
         * its way out, or a goodbye pass having pruned a scope's cache, in which case ifindex and
         * family name what changed. Reconcile every
         * querier that could hold records from what went away against what is left, so its
         * subscribers get their removals; queriers pinned to other links are skipped, their caches
         * did not change. The continuous-query schedules are left alone here: they keep running, and
         * restarting them would collapse the RFC 6762 §5.2 backoff of questions that have no reason
         * to be re-asked — a link flapping reaches this for every scope it takes down. The one
         * caller that does want a prompt re-query, manager_flush_caches(), asks for it itself. */
        assert(m);

        mdns_queriers_revisit(m, ifindex, family, /* match= */ NULL);
}

int mdns_manage_services_answer(DnsServiceQuerier *sq, DnsAnswer *answer, int owner_family) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        DnsAnswerItem *item;
        int r;

        assert(sq);

        /* Notifying subscribers can unregister them — a failed notify below, or the finish: drain —
         * and the last one taken away would free the querier under us. Pin it for the duration. */
        pin = dns_service_querier_ref(sq);

        /* Check for new service added */
        DNS_ANSWER_FOREACH_ITEM(item, answer) {
                int ifindex = mdns_answer_item_ifindex(sq, item);

                r = dns_service_match_and_update(sq->dns_services, item->rr, owner_family, ifindex,
                                                 item->until);
                if (r < 0) {
                        log_debug_errno(r, "Failed to match DNS service: %m");
                        goto finish;
                }
                if (r > 0) {
                        /* Seen again: wind the ladder back (see rr_ttl_state). */
                        sq->rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
                        continue;
                }

                r = browse_service_update_append(
                                &array, item->rr, owner_family, ifindex, BROWSE_SERVICE_UPDATE_ADDED);
                if (r < 0) {
                        log_debug_errno(r, "Failed to append 'added' service event: %m");
                        goto finish;
                }
                if (r == 0)
                        continue;

                r = dns_add_new_service(sq, item->rr, owner_family, ifindex, item->until);
                if (r < 0) {
                        log_debug_errno(r, "Failed to add new DNS service: %m");
                        goto finish;
                }
        }

        /* Check for services removed */
        LIST_FOREACH(dns_services, service, sq->dns_services) {
                if (service->family != owner_family)
                        continue;

                r = mdns_answer_contains_service(sq, answer, service);
                if (r < 0) {
                        log_debug_errno(r, "Failed to match DNS answer against service list: %m");
                        goto finish;
                }
                if (r > 0)
                        continue;

                r = browse_service_update_append(
                                &array, service->rr, owner_family, service->ifindex,
                                BROWSE_SERVICE_UPDATE_REMOVED);
                if (r < 0) {
                        log_debug_errno(r, "Failed to append 'removed' service event: %m");
                        goto finish;
                }

                dns_remove_service(sq, service);
        }

        /* (Re-)arm the querier's maintenance ladder once against the reconciled list — doing it per
         * added/removed instance inside the loops above would make reconciling an answer with M
         * instances O(M²), with M driven by untrusted multicast input. This also disables the timer
         * when no discovered service remains. */
        mdns_querier_schedule_maintenance(sq);

        /* Deliver the same update to every subscriber of this querier. A failure to notify one of
         * them must not keep the others from being served — but the affected subscriber cannot stay
         * subscribed with a silently incomplete view either: the reconciliation has already been
         * applied to the shared service list, so the lost batch would never be re-reported. Error
         * the call out and unregister the subscription, so the client knows to resubscribe for a
         * fresh snapshot (staying registered would get it -EBUSY). Hold a querier reference: the
         * last unregistered subscriber would otherwise tear the querier down under us. */
        LIST_FOREACH(subscribers, sb, sq->subscribers) {
                r = browse_service_notify(sb->link, array);
                if (r < 0) {
                        log_debug_errno(r,
                                        "Failed to notify a browse subscriber, dropping it: %m");
                        (void) sd_varlink_error_errno(sb->link, r);
                        dns_unsubscribe_browse_service(sq->manager, sb->link);
                }
        }

        return 0;

finish:
        /* The events accumulated for this batch are lost with the failure, and the shared service
         * list may already have moved on. Terminate and unregister every subscription instead of
         * carrying on silently -- an errored-out client knows to resubscribe and is then served a
         * fresh snapshot, while a silently dropped batch would leave its view stale with no signal
         * that anything is missing. */
        /* LIST_FOREACH caches the next pointer before the body, so this advances by pointer rather
         * than by re-reading the head. That matters: dns_unsubscribe_browse_service() removes by
         * link from m->dns_service_browsers, and a browser linked here but missing from that map
         * would leave the head unchanged and spin forever, hanging the event loop. The subscribe
         * path does briefly hold exactly that state (it links into sq->subscribers before putting
         * into the map, and its failure path removes from the map first). */
        LIST_FOREACH(subscribers, sb, sq->subscribers) {
                (void) sd_varlink_error_errno(sb->link, r);
                dns_unsubscribe_browse_service(sq->manager, sb->link);
        }

        return r;
}

static int mdns_querier_revisit_cache(DnsServiceQuerier *sq, int owner_family) {
        int r;

        assert(sq);
        assert(sq->manager);

        /* Look the cache up as it is, and in particular without SD_RESOLVED_NO_STALE, whatever the
         * subscriber passed. Nothing is served stale here to begin with — dns_cache_put() forces the
         * retention window to zero for anything but unicast DNS, so an mDNS entry is gone the moment
         * its TTL lapses — while the flag makes dns_cache_lookup() miss the whole key over a single
         * lapsed item. The prune above and the lookup below take separate clock readings, so an
         * instance expiring between them would blank the answer, and the reconciliation would report
         * every still-valid instance of the type as removed. */
        uint64_t lookup_flags = sq->flags & ~SD_RESOLVED_NO_STALE;

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

                if (!dns_service_querier_covers_ifindex(sq, dns_scope_ifindex(scope)))
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
                        return log_debug_errno(r,
                                               "Failed to look up cache for the browse key on scope %s: %m",
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
                                return log_debug_errno(r,
                                                       "Failed to merge cache answer from scope %s: %m",
                                                       dns_scope_ifname(scope) ?: "global");
                }
        }

        /* The callee logs its own failures; the outermost caller decides whether to carry on and
         * says so in its own message. */
        return mdns_manage_services_answer(sq, combined, owner_family);
}

/* Does any of these goodbyes name an instance this querier has reported to its subscribers over the
 * link they arrived on? The records are compared whole, rdata included, so an unrelated instance
 * under the same browsed type does not count.
 *
 * The link has to be compared here and not just by the caller: a querier pinned to a link only ever
 * holds instances from it, but an unpinned one (ifindex 0) reads every link, and a goodbye reaching
 * it over eth0 says nothing about an instance discovered over wlan0. Letting that through would
 * spend the rescue budgets on a link where nothing can be removed, and six of those refuse the
 * rescue the real goodbye needs -- producing exactly the spurious 'removed' this exists to prevent.
 * Both ifindexes have to be known to exclude: a cached record that carries none is not evidence of
 * a different link. */
bool mdns_goodbyes_hit_discovered(DnsServiceQuerier *sq, DnsAnswer *goodbyes, int ifindex) {
        assert(sq);

        LIST_FOREACH(dns_services, service, sq->dns_services) {
                if (ifindex > 0 && service->ifindex > 0 && service->ifindex != ifindex)
                        continue;

                if (dns_answer_contains(goodbyes, service->rr))
                        return true;
        }

        return false;
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
void mdns_queriers_rescue_goodbyes(DnsScope *scope, DnsAnswer *goodbyes) {
        DnsServiceQuerier *sq;
        int r;

        assert(scope);
        assert(scope->manager);

        if (dns_answer_isempty(goodbyes))
                return;

        HASHMAP_FOREACH(sq, scope->manager->dns_service_queriers) {
                if (!dns_service_querier_covers_ifindex(sq, dns_scope_ifindex(scope)))
                        continue;

                /* Cheap gate first. The per-record match below is O(discovered x goodbyes) deep
                 * name comparisons, and both counts are set by whoever is on the link: it can
                 * announce many instances under a browsed type and then put hundreds of forged
                 * TTL-0 records in one packet. Keying off the question rejects a flood aimed at a
                 * type nobody browses in one pass over the answer. */
                r = dns_answer_match_key(goodbyes, sq->key, NULL);
                if (r <= 0) {
                        if (r < 0)
                                log_warning_errno(r, "Failed to match goodbyes, ignoring: %m");
                        continue;
                }

                /* Then the precise one: dns_answer_match_key() looks at owner name, type and class
                 * only, so every PTR under the browsed type passes it — including an instance
                 * nothing ever cached. Only an instance the querier holds can be spuriously
                 * removed, and only that instance is worth a rescue query. */
                if (!mdns_goodbyes_hit_discovered(sq, goodbyes, dns_scope_ifindex(scope)))
                        continue;

                /* The §5.2 floor, shared with the ladder and the continuous schedule: a goodbye
                 * arriving just after either of them put this same question on the wire needs no
                 * rescue of its own, since the answer to that query refreshes the record inside the
                 * §10.1 grace just the same. Checked before the budgets, so a rescue that would be
                 * a duplicate does not spend one. */
                if (!mdns_querier_may_query_now(sq, now(CLOCK_BOOTTIME)))
                        continue;

                /* What the floor above does not bound is the long run, so two budgets remain: the
                 * querier's own, and the scope's, which is what stops one received packet matching
                 * many queriers from multiplying into as many multicasts. The querier's is spent
                 * first, so a querier about to be refused by its own budget does not spend from the
                 * shared one. (There is no burst tier: with the one-second floor ahead of this, a
                 * sub-second second rescue can never reach a budget at all.) */
                if (!ratelimit_below(&sq->goodbye_rescue_ratelimit) ||
                    !ratelimit_below(&scope->goodbye_rescue_ratelimit))
                        continue;

                /* Pinned like the sibling fan-outs: dns_query_go() can complete synchronously,
                 * and a completion that drops the last subscriber would free the querier under
                 * mdns_querier_send_question()'s own use of it. */
                _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin =
                        dns_service_querier_ref(sq);

                r = mdns_querier_send_question(pin, /* cache_ok= */ false);
                if (r < 0)
                        log_warning_errno(r, "Failed to send mDNS rescue query for a goodbye, ignoring: %m");
        }
}

void mdns_queriers_notify_unsolicited_updates(DnsScope *scope, DnsAnswer *answer, int owner_family) {
        DnsServiceQuerier *sq;
        int r;

        assert(scope);
        assert(scope->manager);

        if (!answer)
                return;

        HASHMAP_FOREACH(sq, scope->manager->dns_service_queriers) {
                if (!dns_service_querier_covers_ifindex(sq, dns_scope_ifindex(scope)))
                        continue;

                r = dns_answer_match_key(answer, sq->key, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to match answer key against a querier, ignoring: %m");
                        continue;
                }
                if (r == 0)
                        continue;

                /* Pinned for the same reason as the goodbye fan-out above. */
                _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin =
                        dns_service_querier_ref(sq);

                r = mdns_querier_revisit_cache(pin, owner_family);
                if (r < 0)
                        log_warning_errno(r, "Failed to revisit cache for %s, ignoring: %m",
                                          af_to_ipv4_ipv6(owner_family));
        }
}

static int on_mdns_querier_next_query(sd_event_source *s, uint64_t usec, void *userdata) {
        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        bool first;
        int r;

        sq = dns_service_querier_ref(ASSERT_PTR(userdata));

        /* Re-arm before issuing anything: a negative return from the handler would make sd-event
         * disable the source, silently ending the continuous query for every subscriber sharing
         * this querier — with late joiners then attaching to a dead querier. A failure of the query
         * below then costs one interval rather than the subscription. (A failure of the re-arm
         * itself still ends the schedule; re-arming an existing source does not allocate, so that
         * is not a case worth carrying recovery for, and dns_browse_services_restart() covers it.) */
        first = !sq->initial_query_done;
        sq->initial_query_done = true;
        sq->delay = mdns_calculate_next_query_delay(sq->delay);

        r = event_reset_time_relative(
                        sq->manager->event,
                        &sq->schedule_event,
                        CLOCK_BOOTTIME,
                        sq->delay,
                        /* accuracy= */ 0,
                        on_mdns_querier_next_query,
                        sq,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to schedule next continuous browse query, ignoring: %m");

        /* RFC 6762 Section 5.2 outlines timing requirements for continuous queries. Only this
         * schedule's first query may be served from the cache; every later one exists to poke the
         * network. (A joining subscriber's catch-up is cache-served too, on its own account.)
         * The one-second floor applies here as much as to the other emitters -- a ladder rung or a
         * rescue may have just asked this very question -- and skipping costs nothing, since the
         * backoff above has already been advanced and re-armed. */
        if (!mdns_querier_may_query_now(sq, now(CLOCK_BOOTTIME))) {
                log_debug("Browse question was just asked, skipping this scheduled query.");
                return 0;
        }

        r = mdns_querier_send_question(sq, /* cache_ok= */ first);
        if (r < 0)
                log_warning_errno(r, "Failed to send continuous browse query, ignoring: %m");

        return 0;
}

/* Restart the querier's continuous query from the top: back to a zero delay, with the next (i.e.
 * immediate) query re-entering the RFC 6762 §5.2 doubling ladder. */
static void mdns_querier_restart_schedule(DnsServiceQuerier *sq) {
        int r;

        assert(sq);

        sq->delay = 0;

        r = event_reset_time_relative(
                        sq->manager->event,
                        &sq->schedule_event,
                        CLOCK_BOOTTIME,
                        /* usec= */ 0,
                        /* accuracy= */ 0,
                        on_mdns_querier_next_query,
                        sq,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to restart continuous browse query, ignoring: %m");
}

/* Re-ask the browse questions on the given link (ifindex 0: everywhere), each from the top of its
 * RFC 6762 §5.2 ladder. Unlike the cache revisits there is no family to select on: a querier runs
 * one schedule for its question, not one per address family. */
void dns_browse_services_restart(Manager *m, int ifindex) {
        DnsServiceQuerier *sq;

        assert(m);

        HASHMAP_FOREACH(sq, m->dns_service_queriers) {
                if (!dns_service_querier_covers_ifindex(sq, ifindex))
                        continue;

                /* Pinned across the revisit: it can drop the last subscriber and free the querier,
                 * as the sibling fan-outs document. */
                _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *pin =
                        dns_service_querier_ref(sq);

                mdns_querier_restart_schedule(pin);
        }

        /* The restarted queries go to the wire on purpose -- a browser that just gained a scope has
         * to ask on the link that came up, and a still-valid cache elsewhere would answer without
         * multicasting anything there. That leaves the warm caches of the other links unreconciled
         * until the answers arrive, so reconcile against them now. (manager_flush_caches() purges
         * immediately before restarting, so for that caller this pass runs over caches it just
         * emptied and finds nothing.) */
        mdns_queriers_revisit(m, ifindex, AF_UNSPEC, /* match= */ NULL);
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

/* The browsers map owns its entries: dropping it (manager teardown) frees them, while
 * hashmap_remove() — how a single subscription goes away — hands the browser back instead. */
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                dns_service_browser_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                DnsServiceBrowser,
                dns_service_browser_free);

DEFINE_PRIVATE_HASH_OPS(
                dns_service_querier_hash_ops,
                DnsServiceQuerier,
                dns_service_querier_hash_func,
                dns_service_querier_compare_func);

/* Bring a subscriber that joined an already-running querier up to speed: synthesize "added" events
 * for everything discovered so far, mirroring what a first cache-served query would have yielded. */
static int dns_service_browser_send_snapshot(DnsServiceBrowser *sb) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(sb);
        assert(sb->querier);

        LIST_FOREACH(dns_services, service, sb->querier->dns_services) {
                r = browse_service_update_append(
                                &array, service->rr, service->family, service->ifindex,
                                BROWSE_SERVICE_UPDATE_ADDED);
                if (r < 0)
                        return r;
        }

        return browse_service_notify(sb->link, array);
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
                /* Bounds a sustained goodbye flood per querier; the paired per-scope tier and
                 * the coupling between the two live with the defines. There is no burst tier: the
                 * §5.2 floor ahead of this refuses a second rescue inside the same second anyway,
                 * so a burst could never be reached. See mdns_queriers_rescue_goodbyes(). */
                .goodbye_rescue_ratelimit = { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                              MDNS_RESCUE_RATELIMIT_QUERIER_BURST },
        };

        r = event_reset_time_relative(
                        m->event,
                        &sq->schedule_event,
                        CLOCK_BOOTTIME,
                        /* usec= */ 0,
                        /* accuracy= */ 0,
                        on_mdns_querier_next_query,
                        sq,
                        /* priority= */ 0,
                        "mdns-next-query-schedule",
                        /* force_reset= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to arm the continuous browse query timer: %m");

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
        mdns_querier_abort_query(sq);
}

int dns_subscribe_browse_service(
                Manager *m,
                sd_varlink *link,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags) {

        _cleanup_(dns_service_querier_unrefp) DnsServiceQuerier *sq = NULL;
        _cleanup_(dns_service_browser_freep) DnsServiceBrowser *sb = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question_idna = NULL, *question_utf8 = NULL;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
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

        /* The querier's identity is (question, ifindex, flags), so only bits that can change what
         * an mDNS browse sees may take part — otherwise two clients asking the same question land
         * on separate queriers, each with its own wire schedule, re-confirmation ladder, §5.2
         * one-second floor and goodbye-rescue budget, defeating the sharing and multiplying
         * exactly what those exist to bound. The mismatch needs no exotic client: an empty flags
         * word means "all protocols" (validate_and_mangle_query_flags()), so flags=0 and
         * flags=SD_RESOLVED_MDNS would otherwise never share.
         *
         * What stays: the mDNS family bits select the scopes; NO_ZONE decides whether the host's
         * own published services answer (dns_transaction_go()'s zone check applies to mDNS like
         * anything else); NO_NETWORK turns the browse into a cache watch. Every other admitted bit
         * is inert for an mDNS PTR browse and is dropped rather than split on: the DNS/LLMNR
         * protocol bits would only add unicast transactions whose answers the mDNS-scope
         * reconciliation never reads, DNSSEC does not run on mDNS (NO_VALIDATE, NO_TRUST_ANCHOR),
         * nothing synthesizes a service-type PTR (NO_SYNTHESIZE), the name is never single-label
         * (RELAX_SINGLE_LABEL), and no DNS-SD responder CNAMEs a browse (NO_CNAME). Dropping
         * NO_CACHE is load-bearing rather than cosmetic: whether a query may be cache-served is
         * decided per query by mdns_querier_send_question()'s cache_ok argument, and a NO_CACHE
         * left in sq->flags would override that for the queries meant to be answered from the
         * cache. NO_STALE has no effect on an mDNS browse — dns_cache_put() retains nothing past
         * its TTL for anything but unicast DNS — and the reconciliation masks it out of its own
         * lookups anyway. */
        flags &= SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_MDNS_IPV6 |
                SD_RESOLVED_NO_ZONE | SD_RESOLVED_NO_NETWORK;

        /* No type is the normal case, not a gap: the callers put the full browse name in 'domain'
         * (TEST-89 passes "_testServiceN._udp.local" that way), and dns_question_new_service_pointer()
         * then asks PTR <domain> as intended. RFC 6763 §9 type enumeration needs no special casing
         * either -- it is the same call with domain=_services._dns-sd._udp.<domain>, and its
         * type-shaped rdata is what the instance-less events described at
         * browse_service_update_append() carry. */
        r = dns_question_new_service_pointer(
                        &question_utf8, type, domain, /* convert_idna= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to create DNS question for UTF8 version: %m");

        /* One querier per browse question: if somebody is asking this already, join them instead of
         * multicasting the same question a second time. */
        DnsServiceQuerier *shared = hashmap_get(
                        m->dns_service_queriers,
                        &(DnsServiceQuerier) {
                                .key = dns_question_first_key(question_utf8),
                                .ifindex = ifindex,
                                .flags = flags,
                        });
        if (shared) {
                sq = dns_service_querier_ref(shared);
                log_debug("Joining existing browse querier for %s.",
                          dns_resource_key_to_string(sq->key, key_str, sizeof key_str));
        } else {
                r = dns_question_new_service_pointer(
                                &question_idna, type, domain, /* convert_idna= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to create DNS question for IDNA version: %m");

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

        r = hashmap_ensure_put(&m->dns_service_browsers, &dns_service_browser_hash_ops, link, sb);
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
                        return log_error_errno(r, "Failed to send initial browse snapshot: %m");
                }
        }

        /* Registered and handed over: the map owns the browser from here, and the query below can
         * even unregister (and free) it before returning — a cache hit completes synchronously, and
         * a failed notify then drops the subscription. Release our own reference to it first, so
         * nothing below can reach it. */
        TAKE_PTR(sb);

        if (shared) {
                /* The shared list can lag reality: an instance the querier missed (lossy multicast,
                 * or it appeared while the question was backed off) is absent from the snapshot,
                 * and the next scheduled query can be up to an hour away. Ask once more, exactly as
                 * a first subscriber's own querier would have: cache-servable, so a warm cache
                 * answers it without touching the wire. The shared schedule stays as it is — the
                 * §5.2 backoff belongs to the question, not to whoever just subscribed, and
                 * resetting it here would let repeated subscriptions drive the query rate.
                 *
                 * Not while a query is already in flight though: the querier tracks a single one, so
                 * asking again would abort it — a ladder query about to refresh the RRset, or a
                 * goodbye rescue — and a client subscribing in a loop could keep the shared question
                 * permanently cancelled for everybody else. That in-flight query's answer reconciles
                 * for every subscriber, this one included. */
                if (sq->in_flight_query)
                        log_debug("Browse query in flight, serving the joining subscriber from it.");
                else if (!mdns_querier_may_query_now(sq, now(CLOCK_BOOTTIME)))
                        /* The §5.2 floor the ladder and the schedule observe applies here too, and
                         * this is the one emitter an unprivileged client triggers on demand: with no
                         * publishers the cache stays cold, so every subscribe would otherwise put
                         * the shared question on the wire again. The emission it would duplicate was
                         * within the last second and reconciles for this subscriber as well. */
                        log_debug("Browse question was just asked, serving the joining "
                                  "subscriber from that.");
                else {
                        r = mdns_querier_send_question(sq, /* cache_ok= */ true);
                        if (r < 0)
                                log_warning_errno(r,
                                                  "Failed to query for a joining subscriber, ignoring: %m");
                }
        }

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

static DnsServiceBrowser* dns_service_browser_free(DnsServiceBrowser *sb) {
        if (!sb)
                return NULL;

        if (sb->querier) {
                dns_service_querier_detach(sb->querier, sb);
                sb->querier = dns_service_querier_unref(sb->querier);
        }

        sb->link = sd_varlink_unref(sb->link);

        return mfree(sb);
}

static DnsServiceQuerier* dns_service_querier_free(DnsServiceQuerier *sq) {
        if (!sq)
                return NULL;

        assert(!sq->subscribers);

        LIST_CLEAR(dns_services, sq->dns_services, dnssd_discovered_service_free);

        sq->schedule_event = sd_event_source_disable_unref(sq->schedule_event);
        sq->maintenance_event = sd_event_source_disable_unref(sq->maintenance_event);

        sq->question_idna = dns_question_unref(sq->question_idna);
        sq->question_utf8 = dns_question_unref(sq->question_utf8);
        sq->key = dns_resource_key_unref(sq->key);

        return mfree(sq);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(DnsServiceQuerier, dns_service_querier, dns_service_querier_free);
