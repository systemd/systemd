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

static unsigned n_superseded;

static void note_supersession(DnsQuery *q) {
        n_superseded++;
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

        /* A short TTL is not special here: a publisher may legitimately announce with TTL 1, and
         * no goodbye timer is armed for that (it is gated on TTL 0), so keeping the old expiry
         * would anchor the shared ladder past the point the cache drops the record. Only the
         * decision to remove belongs to the goodbye path. */
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
 * completion handler then frees it. The querier tracks its query by pointer, so the pointer has
 * to be stored before the start and gone once the handler returns; a manager without any scope
 * makes the completion synchronous. */
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

        /* Whether the query already finished inside that call is up to the environment, so end
         * it explicitly otherwise, and pin what the tracking exists for either way: the querier
         * lets go of the query whichever way it ends, and neither it nor the manager is left
         * holding anything. */
        if (sq.in_flight_query)
                dns_query_complete(sq.in_flight_query, DNS_TRANSACTION_ABORTED);

        ASSERT_NULL(sq.in_flight_query);
        ASSERT_EQ(sq.n_ref, 1u);
        ASSERT_EQ(manager.n_dns_queries, 0u);
}

/* The ladder's section 5.2 floor: a rung landing within a second of the continuous query advances
 * and re-arms but sends nothing, since that query brings back the re-confirmation this rung would
 * ask for. A query still pending is the witness: a send supersedes it, the floor leaves it alone. */
TEST(mdns_querier_maintenance_honours_query_floor) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        Manager manager = {};
        /* Declared after the manager it is listed on, so that it is freed first. */
        _cleanup_(dns_query_freep) DnsQuery *pending = NULL;

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local"));
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        ASSERT_OK(dns_query_new(&manager, &pending, question, question, /* question_bypass= */ NULL,
                                /* ifindex= */ 0, SD_RESOLVED_MDNS));
        pending->complete = note_supersession;
        n_superseded = 0;

        DnsServiceQuerier sq = {
                .n_ref = 1,
                .manager = &manager,
                .question_idna = question,
                .question_utf8 = question,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT,
                .in_flight_query = pending,
                .last_wire_query_usec = now(CLOCK_BOOTTIME),
        };

        mdns_querier_run_maintenance(&sq);

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_EQ(n_superseded, 0u);
        ASSERT_PTR_EQ(sq.in_flight_query, pending);

        /* Control: with the floor lifted the same rung sends, superseding the pending query. */
        sq.rr_ttl_state = DNS_RECORD_TTL_STATE_80_PERCENT;
        sq.last_wire_query_usec = usec_sub_unsigned(now(CLOCK_BOOTTIME), USEC_PER_SEC);
        mdns_querier_run_maintenance(&sq);

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_EQ(n_superseded, 1u);
        if (sq.in_flight_query)
                dns_query_complete(sq.in_flight_query, DNS_TRANSACTION_ABORTED);
        ASSERT_NULL(sq.in_flight_query);
        ASSERT_EQ(sq.n_ref, 1u);
}

/* The terminal rung reconciles the cache and starts the ladder over. With no scope and no
 * discovered service there is nothing to remove and nothing to re-arm against, but the rung must
 * still be reset, no query issued, and the handler must return success so that sd-event keeps
 * the source. */
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

/* The other half of the terminal rung: it reconciles before deciding. With a discovered service
 * on the list and no scope left that could answer for it, the pass must drop it and emit the
 * removal; a branch that just rescheduled would leave the service listed forever. */
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

/* The long end: the span is the cache's lifetime, capped at CACHE_TTL_MAX_USEC, not the wire
 * TTL. A peer announcing a multi-hour TTL with the entry nonetheless expiring soon must keep its
 * intermediate rungs, which the unclamped span would put in the past, switching re-confirmation
 * off for the shared ladder. */
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
