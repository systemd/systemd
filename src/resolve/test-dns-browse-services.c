/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "resolved-dns-browse-services.h"
#include "resolved-manager.h"
#include "tests.h"
#include "time-util.h"

static DnsResourceRecord *new_test_service_rr(uint32_t ttl) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local");
        ASSERT_NOT_NULL(rr);

        rr->ttl = ttl;
        rr->ptr.name = strdup("Same Service._http._tcp.local");
        ASSERT_NOT_NULL(rr->ptr.name);

        return rr;
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

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 75));
        ASSERT_EQ(service.until, (usec_t) 100);

        rr = dns_resource_record_unref(rr);
        ASSERT_NOT_NULL(rr = new_test_service_rr(1));
        service.rr = rr;
        service.until = 10;

        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, 200));
        ASSERT_EQ(service.until, (usec_t) 10);
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
TEST(mdns_querier_maintenance_query_completing_synchronously) {
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

        ASSERT_OK(mdns_querier_run_maintenance(&sq));

        /* The rung advanced, the query was issued and is gone again, and nothing leaked. */
        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_85_PERCENT);
        ASSERT_NULL(sq.maintenance_query);
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

        ASSERT_OK(mdns_querier_run_maintenance(&sq));

        ASSERT_EQ(sq.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_NULL(sq.maintenance_query);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
