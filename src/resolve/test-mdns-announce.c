/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "macro.h"
#include "resolved-mdns.h"
#include "string-util.h"
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

/* A TXT record with a single character string of the given size. */
static DnsResourceRecord* txt_rr(const char *name, size_t item_size) {
        DnsResourceRecord *rr;
        DnsTxtItem *item;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT, name);
        ASSERT_NOT_NULL(rr);
        rr->ttl = 120;

        item = malloc0(offsetof(DnsTxtItem, data) + item_size + 1);
        ASSERT_NOT_NULL(item);
        item->length = item_size;
        memset(item->data, 'x', item_size);
        rr->txt.items = item;

        return rr;
}

/* The wire size one record takes at the start of a fresh packet. The test names below share no
 * suffix (except where a testcase says so), so compression never shrinks later occurrences and
 * every record costs this much. */
static size_t rr_wire_size(DnsResourceRecord *rr) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        size_t before;

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_MDNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        before = p->size;
        ASSERT_OK(dns_packet_append_rr(p, rr, /* flags= */ 0, /* start= */ NULL, /* rdata_start= */ NULL));

        return p->size - before;
}

/* Every returned packet must parse back on its own: a rollback on a full packet may leave no
 * truncated trailing data behind. Returns the owner name of every answer record, in packet order and
 * within a packet in answer order, so the caller can pin that each record went out exactly once and
 * in the order it was handed over -- a total count would not notice one record emitted twice while
 * another went missing. Releases the packets and the array. */
static char** check_and_free_packets(DnsPacket **packets, size_t n_packets) {
        _cleanup_strv_free_ char **names = NULL;
        DnsResourceRecord *rr;

        FOREACH_ARRAY(p, packets, n_packets) {
                /* Positive, not just non-negative: dns_packet_validate_reply() returns 0 rather than
                 * an error for a packet whose header says "query", so ASSERT_OK would accept one.
                 * QR and AA are what make this an authoritative response (RFC 6762 section 18.4). */
                ASSERT_OK_POSITIVE(dns_packet_validate_reply(*p));
                ASSERT_EQ(DNS_PACKET_QR(*p), 1);
                ASSERT_EQ(DNS_PACKET_AA(*p), 1);
                ASSERT_OK(dns_packet_extract(*p));

                DNS_ANSWER_FOREACH(rr, (*p)->answer)
                        ASSERT_OK(strv_extend(&names, dns_resource_key_name(rr->key)));
        }

        dns_packet_unref_array(packets, n_packets);
        return TAKE_PTR(names);
}

/* The RFC 6762 section 17 ceiling minus the headers each family puts on the wire. Spelled out rather
 * than re-derived from udp_header_size(): a test that recomputes the formula under test only pins
 * that it was applied twice the same way. IPv6 additionally loses the 8-byte Fragment header. */
#define EXPECTED_FRAGMENTED_MAX_IPV4 (9000U - 20U - 8U)
#define EXPECTED_FRAGMENTED_MAX_IPV6 (9000U - 40U - 8U - 8U)

TEST(mdns_announcement_max_sizes_without_a_link) {
        size_t max_size, fragmented_max;

        /* No link, so no MTU: packets are cut to what a host of the family must accept
         * unfragmented, not to section 17's ceiling. That ceiling is the bound for a datagram
         * deliberately fragmented to carry one oversized record; packing an announcement to it
         * would put dozens of records into a datagram every ordinary link fragments. The two
         * bounds must stay apart for the lone-oversized-RR path to remain reachable at all, which
         * is what the strict comparisons below are for. */
        mdns_announcement_max_sizes(AF_INET, /* link_mtu= */ 0, &max_size, &fragmented_max);
        ASSERT_EQ(fragmented_max, (size_t) EXPECTED_FRAGMENTED_MAX_IPV4);
        ASSERT_EQ(max_size, (size_t) (MDNS_PACKET_UNKNOWN_MTU_IPV4 - 20U - 8U));
        ASSERT_LT(max_size, fragmented_max);

        mdns_announcement_max_sizes(AF_INET6, /* link_mtu= */ 0, &max_size, &fragmented_max);
        ASSERT_EQ(fragmented_max, (size_t) EXPECTED_FRAGMENTED_MAX_IPV6);
        ASSERT_EQ(max_size, (size_t) (MDNS_PACKET_UNKNOWN_MTU_IPV6 - 40U - 8U));
        ASSERT_LT(max_size, fragmented_max);
}

TEST(mdns_announcement_max_sizes_from_the_link_mtu) {
        size_t max_size, fragmented_max;

        /* An Ethernet link: packets are cut to the MTU, while a lone oversized record may still rely
         * on fragmentation up to the ceiling. */
        mdns_announcement_max_sizes(AF_INET, /* link_mtu= */ 1500, &max_size, &fragmented_max);
        ASSERT_EQ(max_size, 1500U - 20U - 8U);
        ASSERT_EQ(fragmented_max, (size_t) EXPECTED_FRAGMENTED_MAX_IPV4);

        mdns_announcement_max_sizes(AF_INET6, /* link_mtu= */ 1500, &max_size, &fragmented_max);
        ASSERT_EQ(max_size, 1500U - 40U - 8U);
        ASSERT_EQ(fragmented_max, (size_t) EXPECTED_FRAGMENTED_MAX_IPV6);
}

TEST(mdns_announcement_max_sizes_caps_a_jumbo_mtu) {
        size_t max_size, fragmented_max;

        /* A jumbo-frame link would let an unfragmented packet exceed the section 17 ceiling, so the
         * ceiling has to bind the MTU-derived size too -- this is the case the cap exists for.
         * DNS_PACKET_SIZE_MAX is larger still, so nothing may derive a size from it either. */
        ASSERT_GT((size_t) DNS_PACKET_SIZE_MAX, (size_t) MDNS_PACKET_FRAGMENTED_SIZE_MAX);

        mdns_announcement_max_sizes(AF_INET, /* link_mtu= */ 9216, &max_size, &fragmented_max);
        ASSERT_EQ(max_size, fragmented_max);
        ASSERT_EQ(max_size, (size_t) EXPECTED_FRAGMENTED_MAX_IPV4);

        mdns_announcement_max_sizes(AF_INET6, /* link_mtu= */ 9216, &max_size, &fragmented_max);
        ASSERT_EQ(max_size, fragmented_max);
        ASSERT_EQ(max_size, (size_t) EXPECTED_FRAGMENTED_MAX_IPV6);
}

TEST(mdns_announcement_max_sizes_ignores_an_mtu_too_small_to_carry_a_packet) {
        size_t max_size, fragmented_max;
        int family;

        /* An MTU that leaves no room for a DNS header past the IP/UDP ones is unusable: deriving a
         * packet size from it yields one no record can ever fit into (or, below the headers, a
         * size_t underflow), and the whole announcement would be silently skipped record by record.
         * So the derivation falls back to the no-link default. Checked right at the boundary and
         * one byte below the headers alone. */
        FOREACH_ARGUMENT(family, AF_INET, AF_INET6) {
                size_t no_link_max, no_link_fragmented;

                mdns_announcement_max_sizes(family, /* link_mtu= */ 0, &no_link_max, &no_link_fragmented);

                mdns_announcement_max_sizes(family, udp_header_size(family) + DNS_PACKET_HEADER_SIZE,
                                            &max_size, &fragmented_max);
                ASSERT_EQ(max_size, no_link_max);
                ASSERT_EQ(fragmented_max, no_link_fragmented);

                mdns_announcement_max_sizes(family, udp_header_size(family) - 1,
                                            &max_size, &fragmented_max);
                ASSERT_EQ(max_size, no_link_max);
                ASSERT_EQ(fragmented_max, no_link_fragmented);

                /* One byte of headroom past the boundary does derive from the MTU, so the assertions
                 * above are not just restating the default. */
                mdns_announcement_max_sizes(family, udp_header_size(family) + DNS_PACKET_HEADER_SIZE + 1,
                                            &max_size, &fragmented_max);
                ASSERT_EQ(max_size, DNS_PACKET_HEADER_SIZE + 1);
        }
}

TEST(mdns_announcement_packetize_empty) {
        DnsPacket **packets = NULL;
        size_t n_packets = SIZE_MAX;

        ASSERT_OK(mdns_announcement_packetize(/* answer= */ NULL, 512, 512,
                                             &packets, &n_packets));
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

        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names, STRV_MAKE("small0", "small1", "small2", "small3", "small4")));
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

        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names,
                               STRV_MAKE("small0",
                                         "small1",
                                         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                         "small2")));
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

        /* The giant is gone; its neighbours went out intact and in order. */
        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names, STRV_MAKE("small0", "small1")));
}

/* The fragmented retry reached without a preceding seal: when the oversized record is the *first*
 * item there is nothing accumulated to flush, so control enters the retry with n_answer already 0
 * and a packet that had nothing appended. That is a different path through the same branch than the
 * mid-answer case above, and the one where a stale n_answer would seal a wrong ancount. */
TEST(mdns_announcement_packetize_oversized_rr_first) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *giant = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0, sz = 0;

        answer = dns_answer_new(3);
        ASSERT_NOT_NULL(answer);

        giant = a_rr("ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
        ASSERT_OK(dns_answer_add(answer, giant, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *first = a_rr("small0");
        sz = rr_wire_size(first);
        ASSERT_GT(rr_wire_size(giant), 2 * sz);
        ASSERT_OK(dns_answer_add(answer, first, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *last = a_rr("small1");
        ASSERT_OK(dns_answer_add(answer, last, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  DNS_PACKET_HEADER_SIZE + 4 * sz,
                                  &packets, &n_packets));

        /* The giant goes out alone in the first packet -- with an ancount of exactly 1, not the
         * count of a packet that was never filled -- and its followers share the second. */
        ASSERT_EQ(n_packets, 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 1u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[1]), 2u);

        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names, STRV_MAKE(dns_resource_key_name(giant->key), "small0", "small1")));
}

/* Nothing emittable at all. The skip must not leave a half-built packet to be sealed with an ancount
 * of zero, and an announcement that has nothing to say is not an error -- the caller sends what it
 * gets back and would otherwise abandon the rest of a withdrawal over one unsendable record. */
TEST(mdns_announcement_packetize_emits_nothing_when_every_rr_is_oversized) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *giant = NULL, *giant2 = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 17;

        answer = dns_answer_new(2);
        ASSERT_NOT_NULL(answer);

        giant = a_rr("ggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg");
        ASSERT_OK(dns_answer_add(answer, giant, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        giant2 = a_rr("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh");
        ASSERT_OK(dns_answer_add(answer, giant2, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE,
                                  DNS_PACKET_HEADER_SIZE,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 0u);
        ASSERT_NULL(packets);
}

/* What a withdrawal *is* on the wire: TTL 0, and the cache-flush bit on the class of a unique
 * record. Both come from the answer item's flags, which packetization has to carry through to
 * dns_packet_append_rr() -- passing 0 there instead would emit positive-TTL "goodbyes" that withdraw
 * nothing, and every other testcase here would still pass. */
TEST(mdns_announcement_packetize_preserves_item_flags) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *bye = NULL, *plain = NULL;
        DnsPacket **packets = NULL;
        DnsAnswerItem *item;
        size_t n_packets = 0, seen = 0;

        answer = dns_answer_new(2);
        ASSERT_NOT_NULL(answer);

        bye = a_rr("bye");
        ASSERT_OK(dns_answer_add(answer, bye, /* ifindex= */ 0,
                                 DNS_ANSWER_GOODBYE|DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));

        /* A negative control in the same packet: without the flags the record keeps its TTL and
         * stays a shared-owner one, so the assertions below discriminate rather than hold for
         * anything that parses. */
        plain = a_rr("stays");
        ASSERT_OK(dns_answer_add(answer, plain, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_SIZE_MAX,
                                  DNS_PACKET_SIZE_MAX,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 1u);
        ASSERT_OK_POSITIVE(dns_packet_validate_reply(packets[0]));
        ASSERT_EQ(DNS_PACKET_QR(packets[0]), 1);
        ASSERT_EQ(DNS_PACKET_AA(packets[0]), 1);
        ASSERT_OK(dns_packet_extract(packets[0]));

        /* Reading a packet turns the wire's cache-flush bit into the *absence* of
         * DNS_ANSWER_SHARED_OWNER, so that is what pins it here. */
        DNS_ANSWER_FOREACH_ITEM(item, packets[0]->answer) {
                if (streq(dns_resource_key_name(item->rr->key), "bye")) {
                        ASSERT_EQ(item->rr->ttl, 0u);
                        ASSERT_FALSE(FLAGS_SET(item->flags, DNS_ANSWER_SHARED_OWNER));
                } else {
                        /* Named explicitly, so a record with neither name cannot satisfy the
                         * negative control by falling into this arm. */
                        ASSERT_STREQ(dns_resource_key_name(item->rr->key), "stays");
                        ASSERT_EQ(item->rr->ttl, 120u);
                        ASSERT_TRUE(FLAGS_SET(item->flags, DNS_ANSWER_SHARED_OWNER));
                }

                seen++;
        }
        ASSERT_EQ(seen, 2u);

        dns_packet_unref_array(packets, n_packets);
}

/* A 256-byte character string cannot be encoded by any packet: its length prefix is one byte. That
 * is an encoding error (-E2BIG; an rdata past 64KiB is the -ENOSPC twin), not a size one, and it
 * must cost this record alone -- the encoder rolls the packet back, so the neighbours go out intact
 * and in order rather than the whole announcement being abandoned over one bad record. */
TEST(mdns_announcement_packetize_skips_rr_that_cannot_be_encoded) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *first = NULL, *bad = NULL, *last = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0;

        answer = dns_answer_new(3);
        ASSERT_NOT_NULL(answer);

        first = a_rr("small0");
        ASSERT_OK(dns_answer_add(answer, first, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        bad = txt_rr("bad", 256);
        ASSERT_OK(dns_answer_add(answer, bad, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        last = a_rr("small1");
        ASSERT_OK(dns_answer_add(answer, last, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_SIZE_MAX,
                                  DNS_PACKET_SIZE_MAX,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 1u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 2u);

        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names, STRV_MAKE("small0", "small1")));
}

/* The testcases above use names that share no suffix, so nothing in their packets is ever a
 * compression pointer. DNS-SD names all share one -- .local at the very least -- which is what the
 * split exists for: the compression map is per packet, and a map carried across a boundary (or an
 * entry surviving the rollback of a full packet) would emit a pointer into offsets that only exist
 * in the previous packet. So: names sharing a suffix, split across packets. Two records fit a packet
 * compressed or not, so the split is the same either way; what is pinned is that every packet parses
 * back on its own, and that the second record of a packet did compress against the first. */
TEST(mdns_announcement_packetize_compresses_within_a_packet_only) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsPacket **packets = NULL;
        size_t n_packets = 0, sz = 0;

        answer = dns_answer_new(5);
        ASSERT_NOT_NULL(answer);

        FOREACH_STRING(name,
                       "svc0._x._udp.local",
                       "svc1._x._udp.local",
                       "svc2._x._udp.local",
                       "svc3._x._udp.local",
                       "svc4._x._udp.local") {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = a_rr(name);

                sz = rr_wire_size(rr);
                ASSERT_OK(dns_answer_add(answer, rr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));
        }

        ASSERT_OK(mdns_announcement_packetize(
                                  answer,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  DNS_PACKET_HEADER_SIZE + 2 * sz,
                                  &packets, &n_packets));
        ASSERT_EQ(n_packets, 3u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[0]), 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[1]), 2u);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packets[2]), 1u);
        /* A full packet of two uncompressed records would be exactly the bound. */
        ASSERT_LT(packets[0]->size, DNS_PACKET_HEADER_SIZE + 2 * sz);
        ASSERT_LT(packets[1]->size, DNS_PACKET_HEADER_SIZE + 2 * sz);

        _cleanup_strv_free_ char **names = check_and_free_packets(packets, n_packets);
        ASSERT_TRUE(strv_equal(names,
                               STRV_MAKE("svc0._x._udp.local",
                                         "svc1._x._udp.local",
                                         "svc2._x._udp.local",
                                         "svc3._x._udp.local",
                                         "svc4._x._udp.local")));
}

DEFINE_TEST_MAIN(LOG_DEBUG)
