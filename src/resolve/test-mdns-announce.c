/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "resolved-mdns.h"
#include "strv.h"
#include "tests.h"

static DnsResourceRecord* a_rr(const char *name) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->ttl = 120;
        rr->a.in_addr.s_addr = htobe32(0xC0A80101);

        return rr;
}

/* The wire size one record takes at the start of a fresh packet. The test names share no suffix,
 * so compression never shrinks later occurrences and every record costs this much. */
static size_t rr_wire_size(DnsResourceRecord *rr) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        size_t before;

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        before = p->size;
        ASSERT_OK(dns_packet_append_rr(p, rr, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));

        return p->size - before;
}

/* Every returned packet must parse back on its own: a rollback on a full packet may leave no
 * truncated trailing data behind. Returns the total number of answer RRs across the packets,
 * unreffing them along the way. */
static size_t check_and_free_packets(DnsPacket **packets, size_t n_packets) {
        size_t total = 0;

        FOREACH_ARRAY(p, packets, n_packets) {
                ASSERT_OK(dns_packet_validate_reply(*p));
                ASSERT_OK(dns_packet_extract(*p));
                total += dns_answer_size((*p)->answer);
                dns_packet_unref(*p);
        }

        free(packets);
        return total;
}

TEST(mdns_announcement_packetize_empty) {
        DnsPacket **packets = NULL;
        size_t n_packets = SIZE_MAX;

        ASSERT_OK(mdns_announcement_packetize(NULL, 512, 512, &packets, &n_packets));
        ASSERT_EQ(n_packets, 0u);
        ASSERT_NULL(packets);
}

TEST(mdns_announcement_packetize_splits_at_max_size) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0, sz = 0;

        answer = dns_answer_new(5);
        ASSERT_NOT_NULL(answer);

        FOREACH_STRING(name, "small0", "small1", "small2", "small3", "small4") {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = a_rr(name);

                sz = rr_wire_size(rr);
                ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        }

        /* Exactly two records fit a packet: five records must make three packets, filled in
         * order. */
        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 3u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[1]), 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[2]), 1u);

        ASSERT_EQ(check_and_free_packets(packets, n_packets), 5u);
}

TEST(mdns_announcement_packetize_oversized_rr_within_fragmented_ceiling) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *big = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0, sz = 0, big_sz;

        answer = dns_answer_new(4);
        ASSERT_NOT_NULL(answer);

        /* small, small, big, small — the big record does not fit a packet even alone. */
        FOREACH_STRING(name, "small0", "small1") {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = a_rr(name);

                sz = rr_wire_size(rr);
                ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        }

        big = a_rr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        big_sz = rr_wire_size(big);
        ASSERT_GT(big_sz, 2 * sz);
        ASSERT_OK(dns_answer_add(answer, big, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = a_rr("small2");
        ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        /* The big record must ride alone in a packet sized up to the fragmented ceiling, between
         * the regular packets of its neighbors. */
        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  DNS_PACKET_HEADER_SIZE + big_sz,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 3u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[1]), 1u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[2]), 1u);
        ASSERT_EQ(packets[1]->size, DNS_PACKET_HEADER_SIZE + big_sz);

        ASSERT_EQ(check_and_free_packets(packets, n_packets), 4u);
}

TEST(mdns_announcement_packetize_skips_rr_beyond_fragmented_ceiling) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *giant = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0, sz = 0;

        answer = dns_answer_new(3);
        ASSERT_NOT_NULL(answer);

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *first = a_rr("small0");
        sz = rr_wire_size(first);
        ASSERT_OK(dns_answer_add(answer, first, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        giant = a_rr("ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
        ASSERT_GT(rr_wire_size(giant), 2 * sz);
        ASSERT_OK(dns_answer_add(answer, giant, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *last = a_rr("small1");
        ASSERT_OK(dns_answer_add(answer, last, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        /* With no fragmented headroom the record that fits nowhere is dropped, and its neighbors
         * still go out. */
        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 1u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[1]), 1u);

        ASSERT_EQ(check_and_free_packets(packets, n_packets), 2u);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
