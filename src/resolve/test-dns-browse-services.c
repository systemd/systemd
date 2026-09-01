/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "sd-event.h"

#include "dns-answer.h"
#include "dns-rr.h"
#include "resolved-dns-browse-services.h"
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

        DnsServiceBrowser sb_all = {
                .ifindex = 0,
        };
        DnsServiceBrowser sb_scoped = {
                .ifindex = 2,
        };
        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
        };

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sb_all, answer, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer2, rr, 0, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(mdns_answer_contains_service(&sb_scoped, answer2, &service));

        ASSERT_OK_POSITIVE(dns_answer_add(answer3, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_scoped, answer3, &service));

        sb_scoped.ifindex = 3;
        ASSERT_OK_ZERO(mdns_answer_contains_service(&sb_scoped, answer2, &service));
}

TEST(mdns_service_update_restarts_schedule) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        int enabled;

        ASSERT_OK(sd_event_default(&e));
        ASSERT_NOT_NULL(rr = new_test_service_rr(120));
        ASSERT_OK(sd_event_add_time(e, &s, CLOCK_BOOTTIME, 0, 0, NULL, NULL));

        /* The event source is one-shot, i.e. it is disabled once the 100% maintenance query has been
         * issued. A refreshed record must restart the schedule at 80% and re-arm the source. */
        ASSERT_OK(sd_event_source_set_enabled(s, SD_EVENT_OFF));

        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .until = 10 * USEC_PER_MINUTE,
                .schedule_event = s,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT,
        };

        ASSERT_OK(mdns_service_update(&service, rr, /* t= */ 0, 20 * USEC_PER_MINUTE));
        ASSERT_EQ(service.until, 20 * USEC_PER_MINUTE);
        ASSERT_EQ(service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);

        ASSERT_OK(sd_event_source_get_enabled(s, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_ONESHOT);
}

TEST(mdns_service_update_large_ttl) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_OK(sd_event_default(&e));

        /* TTLs are 32-bit values taken off the network. With a TTL of 2^31 s both 20 * ttl and 2 * ttl
         * wrap when evaluated in 32-bit arithmetic, and a zero jitter range makes random_u64_range()
         * return a value from the full 64-bit range, so the next maintenance query used to be
         * scheduled essentially never. Whatever the jitter, it may not exceed 2% of the TTL. */
        ASSERT_NOT_NULL(rr = new_test_service_rr(UINT32_C(1) << 31));

        usec_t until = 10 * USEC_PER_MINUTE;
        usec_t max = usec_add(until, 2 * (usec_t) rr->ttl * USEC_PER_SEC / 100);

        for (unsigned i = 0; i < 5; i++) {
                _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
                usec_t next;

                ASSERT_OK(sd_event_add_time(e, &s, CLOCK_BOOTTIME, 0, 0, NULL, NULL));

                DnssdDiscoveredService service = {
                        .rr = rr,
                        .family = AF_INET,
                        .ifindex = 2,
                        .schedule_event = s,
                };

                ASSERT_OK(mdns_service_update(&service, rr, /* t= */ 0, until));
                ASSERT_OK(sd_event_source_get_time(s, &next));
                ASSERT_LE(next, max);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
