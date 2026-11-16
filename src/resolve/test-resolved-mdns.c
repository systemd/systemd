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

static bool known_answer_suppresses(
                DnsResourceRecord *our,
                DnsResourceRecord *an,
                DnsResourceRecord *ns,
                DnsResourceRecord *ar) {

        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        p = mdns_query_new(our->key, an, ns, ar);

        return mdns_known_answers_suppress(p->answer, our);
}

TEST(mdns_known_answers_suppress) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *our = NULL, *known = NULL, *other = NULL;

        our = a_rr("host.local", 0xc0000201);   /* 192.0.2.1 */
        known = a_rr("host.local", 0xc0000201);
        other = a_rr("host.local", 0xc0000202); /* 192.0.2.2 */

        ASSERT_FALSE(mdns_known_answers_suppress(NULL, our));

        /* Known answer with at least half of our TTL */
        known->ttl = MDNS_DEFAULT_TTL;
        ASSERT_TRUE(known_answer_suppresses(our, known, NULL, NULL));
        known->ttl = MDNS_DEFAULT_TTL / 2;
        ASSERT_TRUE(known_answer_suppresses(our, known, NULL, NULL));

        /* Known answer with less than half of our TTL, the querier's cache needs to be refreshed */
        known->ttl = MDNS_DEFAULT_TTL / 2 - 1;
        ASSERT_FALSE(known_answer_suppresses(our, known, NULL, NULL));

        /* Different data for the same key */
        ASSERT_FALSE(known_answer_suppresses(our, other, NULL, NULL));

        /* The same RR in the Authority Section (probe query) or in the Additional Section is no known
         * answer */
        known->ttl = MDNS_DEFAULT_TTL;
        ASSERT_FALSE(known_answer_suppresses(our, NULL, known, NULL));
        ASSERT_FALSE(known_answer_suppresses(our, NULL, NULL, known));
}

DEFINE_TEST_MAIN(LOG_DEBUG)
