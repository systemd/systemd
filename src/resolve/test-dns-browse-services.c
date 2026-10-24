/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "dns-answer.h"
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

TEST(dns_service_match_and_update_large_ttl) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        usec_t until, t;

        ASSERT_NOT_NULL(rr = new_test_service_rr(UINT32_C(1) << 31));
        ASSERT_OK(sd_event_new(&e));

        Manager m = {
                .event = e,
        };
        DnsServiceBrowser sb = {
                .manager = &m,
        };
        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .service_browser = &sb,
        };

        ASSERT_OK(sd_event_add_time(e, &service.schedule_event, CLOCK_BOOTTIME, USEC_INFINITY,
                                    /* accuracy= */ 0, /* callback= */ NULL, /* userdata= */ NULL));

        /* With a TTL of 2^31 s, the maintenance time and the jitter range must not wrap around. */
        until = usec_add(now(CLOCK_BOOTTIME), 2 * USEC_PER_HOUR);
        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, until));
        ASSERT_OK(sd_event_source_get_time(service.schedule_event, &t));
        ASSERT_LE(t, until + 2 * (usec_t) rr->ttl * USEC_PER_SEC / 100);

        service.schedule_event = sd_event_source_disable_unref(service.schedule_event);
}

TEST(dns_service_match_and_update_restarts_maintenance) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        usec_t until, t;
        int enabled;

        ASSERT_NOT_NULL(rr = new_test_service_rr(120));
        ASSERT_OK(sd_event_new(&e));

        Manager m = {
                .event = e,
        };
        DnsServiceBrowser sb = {
                .manager = &m,
        };
        DnssdDiscoveredService service = {
                .rr = rr,
                .family = AF_INET,
                .ifindex = 2,
                .service_browser = &sb,
                .rr_ttl_state = DNS_RECORD_TTL_STATE_100_PERCENT,
        };

        /* The one-shot source is off once the 100% point has been reached. */
        ASSERT_OK(sd_event_add_time(e, &service.schedule_event, CLOCK_BOOTTIME, USEC_INFINITY,
                                    /* accuracy= */ 0, /* callback= */ NULL, /* userdata= */ NULL));
        ASSERT_OK(sd_event_source_set_enabled(service.schedule_event, SD_EVENT_OFF));

        /* A refreshed record restarts the schedule at 80% of its TTL. */
        until = usec_add(now(CLOCK_BOOTTIME), 120 * USEC_PER_SEC);
        ASSERT_OK_POSITIVE(dns_service_match_and_update(&service, rr, AF_INET, 2, until));
        ASSERT_EQ(service.rr_ttl_state, DNS_RECORD_TTL_STATE_80_PERCENT);
        ASSERT_OK(sd_event_source_get_enabled(service.schedule_event, &enabled));
        ASSERT_EQ(enabled, SD_EVENT_ONESHOT);
        ASSERT_OK(sd_event_source_get_time(service.schedule_event, &t));
        ASSERT_GE(t, until - 24 * USEC_PER_SEC);
        ASSERT_LT(t, until - 24 * USEC_PER_SEC + 2400 * USEC_PER_MSEC);

        service.schedule_event = sd_event_source_disable_unref(service.schedule_event);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
