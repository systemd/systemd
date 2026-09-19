/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-json.h"

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

/* What a browse reports for a record. An instance is split into its three parts. A service type
 * enumeration answer (RFC 6763 §9) names a type with no instance in front: the type is reported,
 * under an empty name, rather than the enumeration question's own name. */
TEST(browse_service_update_append) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *instance = NULL, *enumerated = NULL,
                *nsec = NULL, *unparsable = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        _cleanup_free_ char *label = NULL;
        sd_json_variant *entry;

        ASSERT_NOT_NULL(instance = new_test_service_rr(120));
        ASSERT_OK_POSITIVE(browse_service_update_append(&array, instance, AF_INET, /* ifindex= */ 2,
                                                        BROWSE_SERVICE_UPDATE_ADDED));

        enumerated = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                  "_services._dns-sd._udp.local");
        ASSERT_NOT_NULL(enumerated);
        ASSERT_NOT_NULL(enumerated->ptr.name = strdup("_ipp._tcp.local"));
        ASSERT_OK_POSITIVE(browse_service_update_append(&array, enumerated, AF_INET, /* ifindex= */ 2,
                                                        BROWSE_SERVICE_UPDATE_ADDED));

        /* Dropped without failing the batch: a record that is not a PTR, such as the NSEC a cache
         * lookup hands back with the PTR key, and a PTR whose target does not parse. */
        nsec = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NSEC, "_http._tcp.local");
        ASSERT_NOT_NULL(nsec);
        ASSERT_OK_ZERO(browse_service_update_append(&array, nsec, AF_INET, /* ifindex= */ 2,
                                                    BROWSE_SERVICE_UPDATE_ADDED));

        unparsable = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local");
        ASSERT_NOT_NULL(unparsable);
        ASSERT_NOT_NULL(label = strrep("a", DNS_LABEL_MAX + 1));
        ASSERT_NOT_NULL(unparsable->ptr.name = strjoin(label, "._http._tcp.local"));
        ASSERT_OK_ZERO(browse_service_update_append(&array, unparsable, AF_INET, /* ifindex= */ 2,
                                                    BROWSE_SERVICE_UPDATE_ADDED));

        ASSERT_EQ(sd_json_variant_elements(array), 2u);

        entry = sd_json_variant_by_index(array, 0);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "name")), "Same Service");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "type")), "_http._tcp");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "domain")), "local");

        entry = sd_json_variant_by_index(array, 1);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "name")), "");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "type")), "_ipp._tcp");
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(entry, "domain")), "local");
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

/* The gate the RFC 6762 §10.1 rescue hangs on: a goodbye earns a rescue, and the budget one
 * costs, only when it names an instance this querier reported. Matching on the question alone
 * would let goodbyes for names nobody holds drain the budget and leave a genuine goodbye
 * unrescued. */
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
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&sq, /* goodbyes= */ NULL, /* ifindex= */ 2, AF_INET));

        ASSERT_NOT_NULL(miss = dns_answer_new(1));
        ASSERT_OK_POSITIVE(dns_answer_add(miss, other, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&sq, miss, /* ifindex= */ 2, AF_INET));

        /* The instance the querier holds: this one is rescuable. */
        ASSERT_NOT_NULL(hit = dns_answer_new(2));
        ASSERT_OK_POSITIVE(dns_answer_add(hit, other, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_add(hit, held, /* ifindex= */ 2, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&sq, hit, /* ifindex= */ 2, AF_INET));

        /* But not over the other family: a removal is reported per family, so an IPv6 goodbye has
         * nothing of this IPv4 discovery to withdraw. */
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&sq, hit, /* ifindex= */ 2, AF_INET6));

        /* And the link half: an unpinned querier reads every link, so the same goodbye reaching
         * it over a link the instance was never discovered on must not earn a rescue. A querier
         * pinned to the link is unaffected, it only holds instances from it. */
        DnsServiceQuerier unpinned = {
                .ifindex = 0,
                .dns_services = &service,
        };
        ASSERT_FALSE(mdns_goodbyes_hit_discovered(&unpinned, hit, /* ifindex= */ 3, AF_INET));
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&unpinned, hit, /* ifindex= */ 2, AF_INET));

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
        ASSERT_TRUE(mdns_goodbyes_hit_discovered(&unpinned_linkless, hit, /* ifindex= */ 3, AF_INET));
}

/* The rescue's spending discipline, observed through the budget counters: the gate refuses
 * before anything is spent, the querier's own budget is charged before the scope's, and an
 * admitted rescue charges each tier exactly once, whether it goes out at once or waits for the
 * RFC 6762 §5.2 floor. The emission's scope restriction needs a live second publisher and is
 * integration territory. */
TEST(mdns_queriers_rescue_goodbyes_spends_budgets_in_order) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *held = NULL, *other = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *goodbyes = NULL, *miss = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        Manager manager = {};

        ASSERT_OK(sd_event_new(&event));
        manager.event = event;

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

        /* The §5.2 floor: this question went to the wire less than a second ago. The rescue is
         * admitted and charged like any other, but waits for the floor to lift, on the scope
         * that admitted it. */
        sq.last_wire_query_usec = now(CLOCK_BOOTTIME);
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_NOT_NULL(sq.rescue_event);
        ASSERT_NULL(sq.in_flight_query);
        ASSERT_EQ(sq.rescue_family, AF_INET);

        /* A repeat on the same scope rides on the waiting rescue and spends nothing. */
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 1u);

        /* One from another scope widens it, on that scope's budget alone -- and only once: a
         * widened rescue reaches every scope, so later goodbyes there ride on it for free. */
        DnssdDiscoveredService service6 = {
                .rr = held,
                .family = AF_INET6,
                .ifindex = 2,
                .until = 100,
        };
        service.dns_services_next = &service6;
        service6.dns_services_prev = &service;
        DnsScope other_scope = {
                .manager = &manager,
                .family = AF_INET6,
                .goodbye_rescue_ratelimit = { MDNS_RESCUE_RATELIMIT_INTERVAL_USEC,
                                              MDNS_RESCUE_RATELIMIT_SCOPE_BURST },
        };
        mdns_queriers_rescue_goodbyes(&other_scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(other_scope.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(sq.rescue_family, AF_UNSPEC);
        mdns_queriers_rescue_goodbyes(&other_scope, goodbyes);
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(other_scope.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 1u);

        /* And it fires once the floor lifts, releasing the timer. */
        ASSERT_OK_POSITIVE(sd_event_run(event, 3 * USEC_PER_SEC));
        ASSERT_NULL(sq.rescue_event);
        if (sq.in_flight_query)
                dns_query_complete(sq.in_flight_query, DNS_TRANSACTION_ABORTED);
        ASSERT_NULL(sq.in_flight_query);

        /* Admitted with the floor clear: exactly one charge on each tier, and nothing deferred. */
        sq.last_wire_query_usec = 0;
        sq.goodbye_rescue_ratelimit.num = 0;
        scope.goodbye_rescue_ratelimit.num = 0;
        mdns_queriers_rescue_goodbyes(&scope, goodbyes);
        ASSERT_EQ(sq.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_EQ(scope.goodbye_rescue_ratelimit.num, 1u);
        ASSERT_NULL(sq.rescue_event);
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

static unsigned n_superseded;

static void note_supersession(DnsQuery *q) {
        n_superseded++;
}

/* The ladder's section 5.2 floor: a rung landing within a second of the continuous query advances
 * and re-arms but sends nothing, since that query brings back the re-confirmation this rung would
 * ask for. A query still pending is the witness: a send supersedes it, the floor leaves it alone. */
TEST(mdns_querier_maintenance_honours_query_floor) {
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_query_freep) DnsQuery *pending = NULL;
        Manager manager = {};

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_PTR, "_http._tcp.local"));
        ASSERT_NOT_NULL(question = dns_question_new(1));
        ASSERT_OK(dns_question_add(question, key, /* flags= */ 0));
        ASSERT_OK(dns_query_new(&manager, &pending, question, question, /* question_bypass= */ NULL,
                                /* ifindex= */ 0, SD_RESOLVED_MDNS));
        pending->complete = note_supersession;

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
