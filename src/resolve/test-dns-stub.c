/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "resolved-dns-stub.h"
#include "string-util.h"
#include "tests.h"

#define N_DNSKEYS 5U
#define DNSKEY_KEY_SIZE 200U

static void make_request(DnsPacket **ret, DnsResourceKey *key, uint16_t max_udp_size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        ASSERT_OK(dns_packet_new_query(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0,
                                       /* dnssec_checking_disabled= */ false));
        DNS_PACKET_HEADER(p)->id = htobe16(42);

        ASSERT_OK(dns_packet_append_key(p, key, 0, NULL));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);

        ASSERT_OK(dns_packet_append_opt(p, max_udp_size,
                                        /* edns0_do= */ false,
                                        /* include_rfc6975= */ false,
                                        /* nsid= */ NULL,
                                        DNS_RCODE_SUCCESS,
                                        /* ret_start= */ NULL));

        ASSERT_OK(dns_packet_extract(p));

        *ret = TAKE_PTR(p);
}

static void make_upstream_reply(DnsPacket **ret, DnsResourceKey *key) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        DNS_PACKET_HEADER(p)->id = htobe16(4711);
        DNS_PACKET_HEADER(p)->flags = htobe16(
                        DNS_PACKET_MAKE_FLAGS(1, 0, 0, 0, 1, 1, 0, 0, DNS_RCODE_SUCCESS));

        ASSERT_OK(dns_packet_append_key(p, key, 0, NULL));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);

        for (unsigned i = 0; i < N_DNSKEYS; i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                ASSERT_NOT_NULL(rr = dns_resource_record_new(key));
                rr->ttl = 3600;
                rr->dnskey.flags = 257;
                rr->dnskey.protocol = 3;
                rr->dnskey.algorithm = DNSSEC_ALGORITHM_RSASHA256;
                rr->dnskey.key_size = DNSKEY_KEY_SIZE;
                ASSERT_NOT_NULL(rr->dnskey.key = malloc(DNSKEY_KEY_SIZE));
                /* Distinct keys, so that nothing is merged */
                memset(rr->dnskey.key, 'a' + i, DNSKEY_KEY_SIZE);

                ASSERT_OK(dns_packet_append_rr(p, rr, 0, NULL, NULL));
        }
        DNS_PACKET_HEADER(p)->ancount = htobe16(N_DNSKEYS);

        /* Bumps ARCOUNT on its own */
        ASSERT_OK(dns_packet_append_opt(p, 1232,
                                        /* edns0_do= */ false,
                                        /* include_rfc6975= */ false,
                                        /* nsid= */ NULL,
                                        DNS_RCODE_SUCCESS,
                                        /* ret_start= */ NULL));

        *ret = TAKE_PTR(p);
}

static void parse_reply(DnsPacket *reply, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        /* The extracted data of 'reply' describes the packet from before it was patched, hence verify a
         * fresh, not yet extracted copy of what is actually sent to the client: every RR the header
         * announces must be present in full, and nothing may follow the last one. */
        ASSERT_OK(dns_packet_dup(&p, reply));

        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);
        for (unsigned i = 0; i < DNS_PACKET_QDCOUNT(p); i++)
                ASSERT_OK(dns_packet_read_key(p, NULL, NULL, NULL));
        for (unsigned i = 0; i < DNS_PACKET_RRCOUNT(p); i++) {
                log_debug("Reading RR %u/%u at offset %zu of %zu",
                          i + 1, DNS_PACKET_RRCOUNT(p), p->rindex, p->size);
                ASSERT_OK(dns_packet_read_rr(p, NULL, NULL, NULL));
        }
        ASSERT_EQ(p->rindex, p->size);

        ASSERT_OK(dns_packet_extract(p));
        ASSERT_EQ(DNS_PACKET_RRCOUNT(p), dns_answer_size(p->answer) + !!p->opt);

        *ret = TAKE_PTR(p);
}

TEST(patch_bypass_reply_packet_truncated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        /* An oversized upstream reply (e.g. received via TCP or from the cache) is proxied back to a UDP
         * client that advertised a 512 byte EDNS0 payload size.

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(&request, key, 512);
        ASSERT_EQ(dns_packet_payload_size_max(request), 512U);

        make_upstream_reply(&original, key);
        ASSERT_GT(original->size, (size_t) dns_packet_payload_size_max(request));

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        ASSERT_LE(reply->size, (size_t) dns_packet_payload_size_max(request));
        ASSERT_TRUE(DNS_PACKET_TC(reply));
        ASSERT_EQ(DNS_PACKET_ID(reply), DNS_PACKET_ID(request));

        parse_reply(reply, &parsed);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(parsed), 1U);
        ASSERT_LE(DNS_PACKET_ANCOUNT(parsed), N_DNSKEYS);

        /* The client asked with EDNS0, hence the truncated reply must still carry an OPT RR */
        ASSERT_NOT_NULL(parsed->opt);
}

TEST(patch_bypass_reply_packet_truncated_large_opt) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_free_ char *nsid = NULL;

        /* The upstream OPT RR doesn't even fit right behind the question. The reply must still carry an OPT
         * RR with the UDP payload size, extended RCODE and flags. Only the options may be dropped. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(&request, key, 512);

        /* Replace the OPT RR by one with DO, an extended RCODE and a large NSID option, making it 495 bytes,
         * which doesn't fit behind the 21 bytes of header and question. */
        make_upstream_reply(&original, key);
        ASSERT_OK_POSITIVE(dns_packet_truncate_opt(original));
        DNS_PACKET_HEADER(original)->flags = htobe16(be16toh(DNS_PACKET_HEADER(original)->flags) |
                                                     (DNS_RCODE_BADCOOKIE & 0xF));
        ASSERT_NOT_NULL(nsid = strrep("x", 480));
        ASSERT_OK(dns_packet_append_opt(original, 1232,
                                        /* edns0_do= */ true,
                                        /* include_rfc6975= */ false,
                                        nsid,
                                        DNS_RCODE_BADCOOKIE,
                                        /* ret_start= */ NULL));

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        ASSERT_LE(reply->size, (size_t) dns_packet_payload_size_max(request));
        ASSERT_TRUE(DNS_PACKET_TC(reply));

        parse_reply(reply, &parsed);

        ASSERT_NOT_NULL(parsed->opt);
        ASSERT_EQ(parsed->opt->opt.data_size, 0U);
        ASSERT_EQ(parsed->opt->key->class, 65536U - 14U - 20U - 8U); /* ADVERTISE_DATAGRAM_SIZE_MAX */
        ASSERT_TRUE(dns_packet_do(parsed));
        ASSERT_EQ(dns_packet_rcode(parsed), DNS_RCODE_BADCOOKIE);

        /* Only the 11 byte fixed part of the OPT RR is retained, which leaves room for two DNSKEY RRs */
        ASSERT_EQ(DNS_PACKET_ANCOUNT(parsed), 2U);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(parsed), 1U);
}

TEST(patch_bypass_reply_packet_truncated_no_edns) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        /* A client that didn't use EDNS0 might still get an upstream packet with an OPT RR, e.g. one cached
         * from an earlier lookup with DO. Its truncated reply must not gain an OPT RR. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        ASSERT_OK(dns_packet_new_query(&request, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0,
                                       /* dnssec_checking_disabled= */ false));
        DNS_PACKET_HEADER(request)->id = htobe16(42);
        ASSERT_OK(dns_packet_append_key(request, key, 0, NULL));
        DNS_PACKET_HEADER(request)->qdcount = htobe16(1);
        ASSERT_OK(dns_packet_extract(request));
        ASSERT_EQ(dns_packet_payload_size_max(request), 512U);

        make_upstream_reply(&original, key);

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        ASSERT_LE(reply->size, (size_t) dns_packet_payload_size_max(request));
        ASSERT_TRUE(DNS_PACKET_TC(reply));

        parse_reply(reply, &parsed);

        ASSERT_NULL(parsed->opt);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(parsed), 0U);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
