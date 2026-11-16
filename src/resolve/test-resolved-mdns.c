/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "resolved-dns-zone.h"
#include "resolved-mdns.h"
#include "tests.h"

static DnsResourceRecord* a_rr(const char *name, uint32_t addr) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->ttl = MDNS_DEFAULT_TTL;
        rr->a.in_addr.s_addr = htobe32(addr);

        return rr;
}

static DnsPacket* mdns_query_new(
                DnsResourceKey *key,
                DnsResourceRecord *an,
                DnsResourceRecord *ns,
                DnsResourceRecord *ar) {

        DnsPacket *p;

        ASSERT_OK(dns_packet_new_query(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, /* dnssec_checking_disabled= */ false));

        ASSERT_OK(dns_packet_append_key(p, key, /* flags= */ 0, /* start= */ NULL));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);

        if (an) {
                ASSERT_OK(dns_packet_append_rr(p, an, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));
                DNS_PACKET_HEADER(p)->ancount = htobe16(1);
        }
        if (ns) {
                ASSERT_OK(dns_packet_append_rr(p, ns, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));
                DNS_PACKET_HEADER(p)->nscount = htobe16(1);
        }
        if (ar) {
                ASSERT_OK(dns_packet_append_rr(p, ar, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));
                DNS_PACKET_HEADER(p)->arcount = htobe16(1);
        }

        ASSERT_OK(dns_packet_extract(p));

        return p;
}

static const DnsAnswerItem* answer_item(DnsAnswer *answer, DnsResourceRecord *rr) {
        DnsAnswerItem *item;

        DNS_ANSWER_FOREACH_ITEM(item, answer)
                if (item->rr == rr)
                        return item;

        assert_not_reached();
}

static bool suppresses(DnsAnswer *known_answers, DnsAnswer *answer, DnsResourceRecord *rr) {
        return mdns_known_answers_suppress(known_answers, answer, answer_item(answer, rr));
}

static bool known_answer_suppresses(
                DnsResourceRecord *our,
                DnsResourceRecord *an,
                DnsResourceRecord *ns,
                DnsResourceRecord *ar) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        p = mdns_query_new(our->key, an, ns, ar);

        ASSERT_OK(dns_answer_add_extend(&answer, our, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));

        return suppresses(p->answer, answer, our);
}

TEST(mdns_known_answers_suppress) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *our = NULL, *known = NULL, *other = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;

        our = a_rr("host.local", 0xc0000201);   /* 192.0.2.1 */
        known = a_rr("host.local", 0xc0000201);
        other = a_rr("host.local", 0xc0000202); /* 192.0.2.2 */

        ASSERT_OK(dns_answer_add_extend(&answer, our, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_FALSE(suppresses(/* known_answers= */ NULL, answer, our));

        /* Known answer with at least half of our TTL */
        known->ttl = MDNS_DEFAULT_TTL;
        ASSERT_TRUE(known_answer_suppresses(our, known, /* ns= */ NULL, /* ar= */ NULL));
        known->ttl = MDNS_DEFAULT_TTL / 2;
        ASSERT_TRUE(known_answer_suppresses(our, known, /* ns= */ NULL, /* ar= */ NULL));

        /* Known answer with less than half of our TTL, the querier's cache needs to be refreshed */
        known->ttl = MDNS_DEFAULT_TTL / 2 - 1;
        ASSERT_FALSE(known_answer_suppresses(our, known, /* ns= */ NULL, /* ar= */ NULL));

        /* Different data for the same key */
        ASSERT_FALSE(known_answer_suppresses(our, other, /* ns= */ NULL, /* ar= */ NULL));

        /* The same RR in the Authority Section (probe query) or in the Additional Section is no known
         * answer */
        known->ttl = MDNS_DEFAULT_TTL;
        ASSERT_FALSE(known_answer_suppresses(our, /* an= */ NULL, known, /* ar= */ NULL));
        ASSERT_FALSE(known_answer_suppresses(our, /* an= */ NULL, /* ns= */ NULL, known));
}

TEST(mdns_known_answers_suppress_rrset) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr2 = NULL, *aaaa = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *known = NULL, *answer = NULL, *shared = NULL;

        rr1 = a_rr("host.local", 0xc0000201); /* 192.0.2.1 */
        rr2 = a_rr("host.local", 0xc0000202); /* 192.0.2.2 */

        aaaa = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "host.local");
        ASSERT_NOT_NULL(aaaa);
        aaaa->ttl = MDNS_DEFAULT_TTL;
        aaaa->aaaa.in6_addr = (struct in6_addr) { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x01 } }; /* 2001:db8::1 */

        ASSERT_OK(dns_answer_add_extend(&known, rr1, /* ifindex= */ 0, DNS_ANSWER_SECTION_ANSWER, /* rrsig= */ NULL));

        /* Only one member of a unique RRset is known: sending the other one with the cache-flush bit set
         * would flush the known one, hence send both */
        ASSERT_OK(dns_answer_add_extend(&answer, rr1, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_OK(dns_answer_add_extend(&answer, rr2, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_FALSE(suppresses(known, answer, rr1));
        ASSERT_FALSE(suppresses(known, answer, rr2));

        /* All members of the RRset are known */
        ASSERT_OK(dns_answer_add_extend(&known, rr2, /* ifindex= */ 0, DNS_ANSWER_SECTION_ANSWER, /* rrsig= */ NULL));
        ASSERT_TRUE(suppresses(known, answer, rr1));
        ASSERT_TRUE(suppresses(known, answer, rr2));

        /* A cache-flush record of another RRset in the same answer (e.g. for an ANY query) neither keeps
         * the known RRset from being suppressed, nor is it suppressed itself */
        ASSERT_OK(dns_answer_add_extend(&answer, aaaa, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_TRUE(suppresses(known, answer, rr1));
        ASSERT_FALSE(suppresses(known, answer, aaaa));

        /* Shared records without the cache-flush bit are suppressed individually */
        ASSERT_OK_POSITIVE(dns_answer_remove_by_rr(&known, rr2));
        ASSERT_OK(dns_answer_add_extend(&shared, rr1, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_OK(dns_answer_add_extend(&shared, rr2, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        ASSERT_TRUE(suppresses(known, shared, rr1));
        ASSERT_FALSE(suppresses(known, shared, rr2));
}

DEFINE_TEST_MAIN(LOG_DEBUG)
