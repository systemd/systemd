/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "resolved-dns-browse-services.h"
#include "resolved-dns-query.h"
#include "resolved-dns-scope.h"
#include "resolved-manager.h"
#include "tests.h"
#include "time-util.h"

static DnsResourceRecord *new_service_rr(const char *instance, uint32_t ttl) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local");
        ASSERT_NOT_NULL(rr);

        rr->ttl = ttl;
        rr->ptr.name = strdup(instance);
        ASSERT_NOT_NULL(rr->ptr.name);

        return rr;
}

static DnsResourceRecord *new_test_service_rr(uint32_t ttl) {
        return new_service_rr("Same Service._http._tcp.local", ttl);
}

/* The flags a scope-restricted emission carries: the goodbye rescue answers on the scope whose
 * budget admitted it, which means swapping the mDNS family bits and nothing else -- a client's
 * NO_ZONE or NO_NETWORK travelling along is what keeps the restricted query behaving like the
 * querier's own. */
TEST(mdns_restrict_flags_to_family) {
        uint64_t flags = SD_RESOLVED_MDNS | SD_RESOLVED_NO_ZONE | SD_RESOLVED_NO_NETWORK;

        ASSERT_EQ(mdns_restrict_flags_to_family(flags, AF_INET),
                  SD_RESOLVED_MDNS_IPV4 | SD_RESOLVED_NO_ZONE | SD_RESOLVED_NO_NETWORK);
        ASSERT_EQ(mdns_restrict_flags_to_family(flags, AF_INET6),
                  SD_RESOLVED_MDNS_IPV6 | SD_RESOLVED_NO_ZONE | SD_RESOLVED_NO_NETWORK);

        /* AF_UNSPEC is the callers that do not restrict: identity. */
        ASSERT_EQ(mdns_restrict_flags_to_family(flags, AF_UNSPEC), flags);

        /* A querier pinned to one family stays on it whichever family the restriction names. */
        ASSERT_EQ(mdns_restrict_flags_to_family(SD_RESOLVED_MDNS_IPV6, AF_INET6),
                  SD_RESOLVED_MDNS_IPV6);
}

/* The gate the RFC 6762 §10.1 rescue hangs on: a goodbye only earns a rescue query, and the budget
 * one costs, when it names an instance this querier actually reported. Matching on the question
 * alone would admit any PTR under the browsed type, so a stream of goodbyes for names nobody holds
 * could drain the budget and leave a genuine goodbye unrescued -- the spurious "removed" the rescue
 * exists to prevent. */
TEST(mdns_goodbyes_hit_discovered_matches_only_held_instances) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *held = NULL, *other = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *hit = NULL, *miss = NULL;

        ASSERT_NOT_NULL(held = new_test_service_rr(120));
        ASSERT_NOT_NULL(other = new_service_rr("Other Service._http._tcp.local", 120));

        DnssdDiscoveredService service = {
                .rr = held,
                .family = AF_INET,
                .ifindex = 2,
                .until = 100,
        };
        DnsServiceQuerier sq = {
                .ifindex = 2,
                .dns_services = &service,
        };

        /* No goodbyes at all, and a goodbye for an instance under the same type that was never
         * discovered: neither is worth a rescue. */
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&sq, /* goodbyes= */ NULL, /* ifindex= */ 2));

        ASSERT_NOT_NULL(miss = dns_answer_new(1));
        ASSERT_OK_POSITIVE(dns_answer_add(miss, other, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&sq, miss, /* ifindex= */ 2));

        /* The instance the querier holds: this one is rescuable. */
        ASSERT_NOT_NULL(hit = dns_answer_new(2));
        ASSERT_OK_POSITIVE(dns_answer_add(hit, other, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_add(hit, held, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&sq, hit, /* ifindex= */ 2));

        /* And the link half. An unpinned querier reads every link, so the same goodbye reaching it
         * over a link the instance was never discovered on must not earn a rescue: nothing there
         * can be removed, and the budget it would spend is what the real goodbye needs. A querier
         * pinned to the link is unaffected, since it only ever holds instances from it. */
        DnsServiceQuerier unpinned = {
                .ifindex = 0,
                .dns_services = &service,
        };
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&unpinned, hit, /* ifindex= */ 3));
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&unpinned, hit, /* ifindex= */ 2));

        /* A record cached without a link is not evidence of a different one, so it still counts. */
        DnssdDiscoveredService linkless = {
                .rr = held,
                .family = AF_INET,
                .ifindex = 0,
                .until = 100,
        };
        DnsServiceQuerier unpinned_linkless = {
                .ifindex = 0,
                .dns_services = &linkless,
        };
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&unpinned_linkless, hit, /* ifindex= */ 3));
}

/* The rescue's spending discipline, observed through the budget counters: the gate and the
 * RFC 6762 §5.2 floor refuse before anything is spent, the querier's own budget is charged
 * before the scope's — so a querier refused by its own tier does not drain the shared one —
 * and an admitted rescue charges each tier exactly once. Whether the emitted query completes
 * synchronously is deliberately not asserted, as in the maintenance tests; the emission's
 * scope restriction needs a live second publisher and is integration territory. */
TEST(mdns_queriers_rescue_goodbyes_spends_budgets_in_order) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *held = NULL, *other = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *goodbyes = NULL, *miss = NULL;
        Manager manager = {};

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local"));
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        ASSERT_NOT_NULL(held = new_test_service_rr(120));
        ASSERT_NOT_NULL(other = new_service_rr("Other Service._http._tcp.local", 120));
        ASSERT_NOT_NULL(goodbyes = dns_answer_new(1));
        ASSERT_OK_POSITIVE(dns_answer_add(goodbyes, held, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_NOT_NULL(miss = dns_answer_new(1));
        ASSERT_OK_POSITIVE(dns_answer_add(miss, other, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));

        DnssdDiscoveredService service = {
                .rr = held,
                .family = AF_INET,
                .ifindex = 2,
                .until = 100,
        };
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .key = key,
                .question_idna = question,
                .question_utf8 = question,
                .dns_services = &service,
                .goodbye_rescue_ratelimit = { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                              MDNS_RESCUE_RATELIMIT_QUERIER_BURST },
        };
        /* Linkless: dns_scope_ifindex() yields 0, which admits every querier, and the
         * goodbye/discovery link comparison never excludes on an unknown link. */
        DnsScope scope = {
                .manager = &manager,
                .family = AF_INET,
                .goodbye_rescue_ratelimit = { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                              MDNS_RESCUE_RATELIMIT_SCOPE_BURST },
        };

        ASSERT_OK(hashmap_ensure_put(&manager.dns_service_queriers, NULL, &sq, &sq));

        /* A goodbye for an instance never discovered stops at the gate: nothing is spent. */
        mdns_queriers_rescue_goodbyes(&scope, miss);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 0u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 0u);

        /* The §5.2 floor: this question went to the wire less than a second ago, so the answer
         * already on its way refreshes the record and the rescue is refused before either
         * budget is consulted. */
        sq.last_wire_query_usec = now(CLOCK_BOOTTIME);
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 0u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 0u);

        /* Admitted: exactly one charge on each tier. */
        sq.last_wire_query_usec = 0;
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 1u);
        if (sq.in_flight_query)
                dns_query_complete(sq.in_flight_query, DNS_TRANSACTION_ABORTED);
        ASSERT_NULL(sq.in_flight_query);

        /* A querier at its own burst is refused by its own tier, and the shared scope tier is
         * not consulted at all — one throttled querier cannot drain the budget the link's other
         * queriers rescue from. (ratelimit_below() counts the refused attempt, hence burst + 1.) */
        sq.last_wire_query_usec = 0;
        sq.goodbye_rescue_ratelimit = (RateLimit) { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                                    MDNS_RESCUE_RATELIMIT_QUERIER_BURST };
        scope.goodbye_rescue_ratelimit = (RateLimit) { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                                       MDNS_RESCUE_RATELIMIT_SCOPE_BURST };
        sq.goodbye_rescue_ratelimit.begin = now(CLOCK_BOOTTIME);
        sq.goodbye_rescue_ratelimit.num = MDNS_RESCUE_RATELIMIT_QUERIER_BURST;
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, MDNS_RESCUE_RATELIMIT_QUERIER_BURST + 1);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 0u);

        ASSERT_EQ(sq.n_ref, 1u);
        ASSERT_EQ(manager.n_dns_queries, 0u);
        hashmap_free(manager.dns_service_queriers);
}

TEST(dns_service_match_and_update_goodbye_and_expiry) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .until = 10,
        };

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 100));
        ASSERT_EQ(service.until, (usec_t) 100);

        /* A shorter expiry is taken too: it is the cache's, and the maintenance ladder is armed off
         * this value — holding on to the longer one would leave the ladder waiting past the point
         * the cache drops the record, and the instance listed until it finally comes around. */
        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 75));
        ASSERT_EQ(service.until, (usec_t) 75);

        /* A short TTL is not special here. It used to be skipped on the grounds that a goodbye
         * rewrites the TTL to 1, but a publisher may legitimately announce with TTL 1 and then no
         * goodbye timer is armed at all (that is gated on TTL 0); keeping the old expiry would
         * anchor the shared ladder past the point the cache drops the record, leaving a phantom
         * instance listed with nothing scheduled to re-check it. Only the decision to remove
         * belongs to the goodbye path. */
        rr = dns_resource_record_unref(rr);
        ASSERT_NOT_NULL(rr = new_test_service_rr(1));
        service.rr = rr;
        service.until = 10;

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 200));
        ASSERT_EQ(service.until, (usec_t) 200);
}

TEST(dns_service_match_and_update_ifindex) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_OK_ZERO(dns_service_match_and_update(&service, rr, AF_INET, 3, 100));
        ASSERT_EQ(service.until, (usec_t) 0);

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 100));
        ASSERT_EQ(service.until, (usec_t) 100);
}

TEST(dns_service_match_and_update_ifindex_list) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnssdDiscoveredService *services = NULL;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnssdDiscoveredService service2 = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .until = 10,
        };
        DnssdDiscoveredService service3 = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 3,
                .until = 20,
        };

        LIST_PREPEND(dns_services, services, &service3);
        LIST_PREPEND(dns_services, services, &service2);

        ASSERT_OK_POSITIVE(dns_service_match_and_update(services, rr, AF_INET, 3, 100));
        ASSERT_EQ(service2.until, (usec_t) 10);
        ASSERT_EQ(service3.until, (usec_t) 100);
}

TEST(dns_service_match_and_update_error) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL, *other = NULL;

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, ".."));
        ASSERT_NOT_NULL(other = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, ".."));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_ERROR(dns_service_match_and_update(&service, other, AF_INET, 2, 100), EINVAL);
}

TEST(mdns_answer_contains_service_ifindex) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer2 = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer3 = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));
        ASSERT_NOT_NULL(answer2 = dns_answer_new(0));
        ASSERT_NOT_NULL(answer3 = dns_answer_new(0));
        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        DnsServiceQuerier sq_all = {
                .ifindex = 0,
        };
        DnsServiceQuerier sq_scoped = {
                .ifindex = 2,
        };
        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sq_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sq_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer2, rr, 0, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sq_scoped, answer2, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer3, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sq_scoped, answer3, &service));

        sq_scoped.ifindex = 3;
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sq_scoped, answer2, &service));
}

/* dns_query_go() completes a query synchronously when no scope matches its question, and the
 * completion handler then frees the query. The ladder tracks its maintenance query by pointer, so the
 * pointer has to be stored before the query is started and be gone again once the handler returns — a
 * manager without any scope makes the completion synchronous. */
TEST(mdns_querier_in_flight_query_is_untracked_when_it_ends) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        Manager manager = {};

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local"));
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));

        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .question_idna = question,
                .question_utf8 = question,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT,
        };

        mdns_querier_run_maintenance(&sq);

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);

        /* Whether the query already finished inside that call is up to the environment — with no
         * scope to send it on it usually completes right away, but nothing here may depend on it.
         * End it explicitly otherwise, and pin what the tracking exists for either way: the querier
         * lets go of the query whichever way it ends, so the pointer cannot dangle, and neither the
         * querier nor the manager is left holding anything. */
        if (sq.in_flight_query)
                dns_query_complete(sq.in_flight_query, DNS_TRANSACTION_ABORTED);

        ASSERT_NULL(sq.in_flight_query);
        ASSERT_EQ(sq.n_ref, 1u);
        ASSERT_EQ(manager.n_dns_queries, 0u);
}

/* The terminal rung used to be a one-shot that returned without rescheduling; now it reconciles the
 * cache and starts the ladder over. With no scope and no discovered service there is nothing to remove
 * and nothing to re-arm against, but the rung must still be reset, no query issued, and the handler
 * must return success so that sd-event keeps the source. */
TEST(mdns_querier_maintenance_terminal_rung_resets_ladder) {
        Manager manager = {};
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT,
        };

        mdns_querier_run_maintenance(&sq);

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_NULL(sq.in_flight_query);
        /* With nothing discovered there is nothing to re-arm against, so the ladder stays off. The
         * companion test below covers the rung that does have something to reconcile. */
        ASSERT_NULL(sq.maintenance_event);
        ASSERT_EQ(sq.n_ref, 1u);
        ASSERT_EQ(manager.n_dns_queries, 0u);
}

/* The other half of the terminal rung: it reconciles before deciding. With a discovered service on
 * the list and no scope left that could still answer for it, the pass must drop it — that removal
 * (and the "removed" event with it) is what the rung exists for, and a branch that just rescheduled
 * without revisiting would leave the service listed forever. */
TEST(mdns_querier_maintenance_terminal_rung_reconciles_services) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        usec_t t = now(CLOCK_BOOTTIME);

        ASSERT_OK(sd_event_new(&event));

        Manager manager = {
                .event = event,
        };
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .ifindex = 2,
        };

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));
        ASSERT_OK(dns_add_new_service(&sq, rr, AF_INET, /* ifindex= */ 2, usec_add(t, 60 * USEC_PER_SEC)));
        sq.rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT;
        ASSERT_NOT_NULL(sq.dns_services);

        mdns_querier_run_maintenance(&sq);

        /* Reconciled away, and with nothing left the ladder winds down instead of re-arming. */
        ASSERT_NULL(sq.dns_services);
        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_NULL(sq.in_flight_query);
        ASSERT_NULL(sq.maintenance_event);
        ASSERT_EQ(sq.n_ref, 1u);
        ASSERT_EQ(manager.n_dns_queries, 0u);
}

/* Every change to the discovered-service list winds the ladder back to 80%, so that a live RRset never
 * ratchets towards the terminal rung and a surviving instance does not inherit the rung the just-removed
 * soonest one had climbed to. */
TEST(mdns_querier_ladder_winds_back_on_add_and_remove) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        DnsServiceQuerier sq = {
                .rr_ttl_state = DNS_RECORD_TTL_STATE_95_PERCENT,
        };

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));

        ASSERT_OK(dns_add_new_service(&sq, rr, AF_INET, /* ifindex= */ 2, /* until= */ 100));
        ASSERT_NOT_NULL(sq.dns_services);
        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);

        sq.rr_ttl_state = DNS_RECORD_TTL_STATE_95_PERCENT;
        dns_remove_service(&sq, sq.dns_services);
        ASSERT_NULL(sq.dns_services);
        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
}

/* ...and so does an answer that merely re-confirms a known instance, refreshing its expiry — which is
 * what every answered maintenance query produces. Nothing is added or removed, so no client
 * notification is attempted; the list stays as it was and the ladder is armed against it. */
TEST(mdns_querier_ladder_winds_back_on_refresh) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        usec_t t = now(CLOCK_BOOTTIME);

        ASSERT_OK(sd_event_new(&event));

        Manager manager = {
                .event = event,
        };
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .ifindex = 2,
        };

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));
        ASSERT_OK(dns_add_new_service(&sq, rr, AF_INET, /* ifindex= */ 2, usec_add(t, 60 * USEC_PER_SEC)));
        sq.rr_ttl_state = DNS_RECORD_TTL_STATE_95_PERCENT;

        ASSERT_OK(dns_answer_add_extend_full(
                          &answer, rr, /* ifindex= */ 2, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL,
                          usec_add(t, 120 * USEC_PER_SEC)));
        ASSERT_OK(mdns_manage_services_answer(&sq, answer, AF_INET));

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_NOT_NULL(sq.dns_services);
        ASSERT_NULL(sq.dns_services->dns_services_next);
        ASSERT_EQ(sq.dns_services->until, usec_add(t, 120 * USEC_PER_SEC));
        ASSERT_NOT_NULL(sq.maintenance_event);

        sq.maintenance_event = sd_event_source_disable_unref(sq.maintenance_event);
        dns_remove_service(&sq, sq.dns_services);
}

/* The short end of the ladder: with 5% of the span under a second, the intermediate rungs would
 * put four multicasts of one question a few hundred milliseconds apart, so the ladder collapses to
 * the single 80% re-confirmation plus the terminal check. A TTL of 2 must step 80% -> terminal,
 * not 80% -> 85%. */
TEST(mdns_querier_maintenance_collapses_short_ttl_ladder) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        usec_t t = now(CLOCK_BOOTTIME);
        usec_t until = usec_add(t, 2 * USEC_PER_SEC);
        usec_t deadline;

        ASSERT_OK(sd_event_new(&event));

        Manager manager = {
                .event = event,
        };
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .ifindex = 2,
        };

        ASSERT_NOT_NULL(rr = new_test_service_rr(2));
        ASSERT_OK(dns_add_new_service(&sq, rr, AF_INET, /* ifindex= */ 2, until));

        mdns_querier_run_maintenance(&sq);

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_100_PERCENT);

        /* The terminal rung is the expiry check itself: armed at the record's expiry, no jitter. */
        ASSERT_NOT_NULL(sq.maintenance_event);
        ASSERT_OK(sd_event_source_get_time(sq.maintenance_event, &deadline));
        ASSERT_EQ(deadline, until);

        sq.maintenance_event = sd_event_source_disable_unref(sq.maintenance_event);
        dns_remove_service(&sq, sq.dns_services);
}

/* The long end: the span is the cache's lifetime, which calculate_until_valid() caps at
 * CACHE_TTL_MAX_USEC, not the wire TTL. A peer announcing a multi-hour TTL with the entry
 * nonetheless expiring soon must keep its intermediate rungs -- measured back from the expiry with
 * the *clamped* span, the next one is still ahead -- where the unclamped span would put every rung
 * but the terminal in the past and switch re-confirmation off for the shared ladder. */
TEST(mdns_querier_maintenance_span_is_clamped_not_wire_ttl) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        usec_t t = now(CLOCK_BOOTTIME);
        usec_t until = usec_add(t, 30 * USEC_PER_MINUTE);
        usec_t deadline;

        ASSERT_OK(sd_event_new(&event));

        Manager manager = {
                .event = event,
        };
        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .ifindex = 2,
        };

        /* 100000s of wire TTL against a 2h cap; the entry expires half an hour out. */
        ASSERT_NOT_NULL(rr = new_test_service_rr(100000));
        ASSERT_OK(dns_add_new_service(&sq, rr, AF_INET, /* ifindex= */ 2, until));

        mdns_querier_run_maintenance(&sq);

        /* One step up the ladder, and a deadline before the expiry: the 85% rung measured back with
         * the clamped span. Unclamped, every rung but the terminal lies in the past -- the state
         * would race to the terminal and the deadline land on the expiry itself. */
        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_NOT_NULL(sq.maintenance_event);
        ASSERT_OK(sd_event_source_get_time(sq.maintenance_event, &deadline));
        ASSERT_LT(deadline, until);

        sq.maintenance_event = sd_event_source_disable_unref(sq.maintenance_event);
        dns_remove_service(&sq, sq.dns_services);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
