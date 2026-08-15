/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/socket.h>

#include "dns-answer.h"
#include "dns-rr.h"
#include "resolved-dns-browse-services.h"
#include "tests.h"

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

        ASSERT_EQ(dns_service_match_and_update(&service, rr, AF_INET, 2, 100), 1);
        ASSERT_EQ(service.until, (usec_t) 100);

        ASSERT_EQ(dns_service_match_and_update(&service, rr, AF_INET, 2, 75), 1);
        ASSERT_EQ(service.until, (usec_t) 100);

        rr = dns_resource_record_unref(rr);
        ASSERT_NOT_NULL(rr = new_test_service_rr(1));
        service.rr = rr;
        service.until = 10;

        ASSERT_EQ(dns_service_match_and_update(&service, rr, AF_INET, 2, 200), 1);
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

        ASSERT_EQ(dns_service_match_and_update(&service, rr, AF_INET, 3, 100), 0);
        ASSERT_EQ(service.until, (usec_t) 0);

        ASSERT_EQ(dns_service_match_and_update(&service, rr, AF_INET, 2, 100), 1);
        ASSERT_EQ(service.until, (usec_t) 100);
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
        ASSERT_EQ(mdns_answer_contains_service(&sb_all, answer, &service), 0);

        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr, 2, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_EQ(mdns_answer_contains_service(&sb_all, answer, &service), 1);

        ASSERT_OK_POSITIVE(dns_answer_add(answer2, rr, 0, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_EQ(mdns_answer_contains_service(&sb_scoped, answer2, &service), 1);

        ASSERT_OK_POSITIVE(dns_answer_add(answer3, rr, 3, DNS_ANSWER_CACHEABLE, /* rrsig= */ NULL));
        ASSERT_EQ(mdns_answer_contains_service(&sb_scoped, answer3, &service), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
