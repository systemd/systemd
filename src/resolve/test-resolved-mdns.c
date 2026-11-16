/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-answer.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "resolved-mdns.h"
#include "tests.h"

static DnsResourceRecord* make_a(const char *name, uint32_t addr, uint32_t ttl) {
        DnsResourceRecord *rr;

        ASSERT_NOT_NULL(rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name));
        rr->a.in_addr.s_addr = htobe32(addr);
        rr->ttl = ttl;

        return rr;
}

static DnsAnswer* make_our_answer(void) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL;
        DnsAnswer *answer;

        ASSERT_NOT_NULL(answer = dns_answer_new(0));

        rr1 = make_a("host1.local", 0xc0a80101, 120);
        rr2 = make_a("host2.local", 0xc0a80102, 120);
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr1, 1, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_OK_POSITIVE(dns_answer_add(answer, rr2, 1, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));

        return answer;
}

static void add_known(
                DnsAnswer *known,
                const char *name,
                uint32_t addr,
                uint32_t ttl,
                DnsAnswerFlags flags) {

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        rr = make_a(name, addr, ttl);
        ASSERT_OK_POSITIVE(dns_answer_add(known, rr, 1, flags, /* rrsig= */ NULL));
}

TEST(mdns_answer_suppress_known_empty) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer();

        ASSERT_OK(mdns_answer_suppress_known(&answer, /* known= */ NULL));
        ASSERT_EQ(dns_answer_size(answer), 2u);
}

TEST(mdns_answer_suppress_known_half_ttl) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer(), *known = NULL;

        /* TTL exactly half of ours: suppressed */
        ASSERT_NOT_NULL(known = dns_answer_new(0));
        add_known(known, "host1.local", 0xc0a80101, 60, DNS_ANSWER_SECTION_ANSWER);

        ASSERT_OK(mdns_answer_suppress_known(&answer, known));
        ASSERT_EQ(dns_answer_size(answer), 1u);
        ASSERT_EQ(dns_answer_size(known), 1u);
}

TEST(mdns_answer_suppress_known_below_half_ttl) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer(), *known = NULL;

        /* TTL below half of ours: the querier's copy is about to expire, answer anyway */
        ASSERT_NOT_NULL(known = dns_answer_new(0));
        add_known(known, "host1.local", 0xc0a80101, 59, DNS_ANSWER_SECTION_ANSWER);

        ASSERT_OK(mdns_answer_suppress_known(&answer, known));
        ASSERT_EQ(dns_answer_size(answer), 2u);
}

TEST(mdns_answer_suppress_known_different_rdata) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer(), *known = NULL;

        /* Same key, different address: not a known answer for our record */
        ASSERT_NOT_NULL(known = dns_answer_new(0));
        add_known(known, "host1.local", 0xc0a801ff, 120, DNS_ANSWER_SECTION_ANSWER);

        ASSERT_OK(mdns_answer_suppress_known(&answer, known));
        ASSERT_EQ(dns_answer_size(answer), 2u);
}

TEST(mdns_answer_suppress_known_authority_section) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer(), *known = NULL;

        /* Records in the Authority section (e.g. a probe's proposed records) are not known answers */
        ASSERT_NOT_NULL(known = dns_answer_new(0));
        add_known(known, "host1.local", 0xc0a80101, 120, DNS_ANSWER_SECTION_AUTHORITY);
        add_known(known, "host2.local", 0xc0a80102, 120, DNS_ANSWER_SECTION_ADDITIONAL);

        ASSERT_OK(mdns_answer_suppress_known(&answer, known));
        ASSERT_EQ(dns_answer_size(answer), 2u);
}

TEST(mdns_answer_suppress_known_all) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = make_our_answer(), *known = NULL;

        ASSERT_NOT_NULL(known = dns_answer_new(0));
        add_known(known, "host1.local", 0xc0a80101, 120, DNS_ANSWER_SECTION_ANSWER);
        add_known(known, "host2.local", 0xc0a80102, 4500, DNS_ANSWER_SECTION_ANSWER);

        ASSERT_OK(mdns_answer_suppress_known(&answer, known));
        ASSERT_TRUE(dns_answer_isempty(answer));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
