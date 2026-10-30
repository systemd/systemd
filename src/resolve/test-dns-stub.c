/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-rr.h"
#include "memory-util.h"
#include "resolved-dns-stub.h"
#include "string-util.h"
#include "tests.h"

#define ADVERTISE_DATAGRAM_SIZE_MAX (65536U-14U-20U-8U)

#define DNSKEY_KEY_SIZE 200U

static void make_request(DnsResourceKey *key, uint16_t max_udp_size, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;

        assert(ret);

        ASSERT_OK(dns_packet_new_query(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0,
                                       /* dnssec_checking_disabled= */ false));
        DNS_PACKET_HEADER(p)->id = htobe16(42);

        ASSERT_OK(dns_packet_append_key(p, key, 0, NULL));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);

        /* Without max_udp_size the client doesn't use EDNS0 */
        if (max_udp_size > 0)
                ASSERT_OK(dns_packet_append_opt(p, max_udp_size,
                                                /* edns0_do= */ false,
                                                /* include_rfc6975= */ false,
                                                /* nsid= */ NULL,
                                                DNS_RCODE_SUCCESS,
                                                /* ret_start= */ NULL));

        ASSERT_OK(dns_packet_extract(p));
        ASSERT_EQ(dns_packet_payload_size_max(p), MAX(max_udp_size, DNS_PACKET_UNICAST_SIZE_MAX));

        *ret = TAKE_PTR(p);
}

static void append_dnskey(DnsPacket *p, DnsResourceKey *key, char fill) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_NOT_NULL(rr = dns_resource_record_new(key));
        rr->ttl = 3600;
        rr->dnskey.flags = 257;
        rr->dnskey.protocol = 3;
        rr->dnskey.algorithm = DNSSEC_ALGORITHM_RSASHA256;
        rr->dnskey.key_size = DNSKEY_KEY_SIZE;
        ASSERT_NOT_NULL(rr->dnskey.key = malloc(DNSKEY_KEY_SIZE));
        memset(rr->dnskey.key, fill, DNSKEY_KEY_SIZE);

        ASSERT_OK(dns_packet_append_rr(p, rr, 0, NULL, NULL));
}

static void make_upstream_reply(DnsResourceKey *key, const char *layout, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        unsigned n[3] = {}, section = 0;

        assert(ret);

        /* 'layout' lists the RRs of the answer, authority and additional sections, separated by '|'. 'O' is
         * the OPT RR, any other character a DNSKEY RR whose key is filled with it, so that all RRs are
         * distinct. Header and question take 21 bytes, each DNSKEY RR 216 bytes, the OPT RR 11 bytes. */

        ASSERT_OK(dns_packet_new(&p, DNS_PROTOCOL_DNS, /* min_alloc_dsize= */ 0, DNS_PACKET_SIZE_MAX));
        DNS_PACKET_HEADER(p)->id = htobe16(4711);
        DNS_PACKET_HEADER(p)->flags = htobe16(
                        DNS_PACKET_MAKE_FLAGS(1, 0, 0, 0, 1, 1, 0, 0, DNS_RCODE_SUCCESS));

        ASSERT_OK(dns_packet_append_key(p, key, 0, NULL));
        DNS_PACKET_HEADER(p)->qdcount = htobe16(1);

        for (const char *c = layout; *c; c++) {
                if (*c == '|') {
                        section++;
                        ASSERT_LT(section, ELEMENTSOF(n));
                        continue;
                }

                if (*c == 'O')
                        ASSERT_OK(dns_packet_append_opt(p, 1232,
                                                        /* edns0_do= */ false,
                                                        /* include_rfc6975= */ false,
                                                        /* nsid= */ NULL,
                                                        DNS_RCODE_SUCCESS,
                                                        /* ret_start= */ NULL));
                else
                        append_dnskey(p, key, *c);

                n[section]++;
        }

        DNS_PACKET_HEADER(p)->ancount = htobe16(n[0]);
        DNS_PACKET_HEADER(p)->nscount = htobe16(n[1]);
        DNS_PACKET_HEADER(p)->arcount = htobe16(n[2]);

        *ret = TAKE_PTR(p);
}

static void parse_reply(DnsPacket *reply, DnsPacket **ret_parsed, char **ret_layout) {
        _cleanup_(dns_packet_unrefp) DnsPacket *p = NULL;
        _cleanup_free_ char *layout = NULL;

        assert(ret_parsed);
        assert(ret_layout);

        /* The extracted data of 'reply' describes the packet from before it was patched, hence verify a
         * fresh, not yet extracted copy of what is actually sent to the client: every RR the header
         * announces must be present in full, and nothing may follow the last one. The RRs are returned in
         * the notation of make_upstream_reply(). */
        ASSERT_OK(dns_packet_dup(&p, reply));

        dns_packet_rewind(p, DNS_PACKET_HEADER_SIZE);
        for (unsigned i = 0; i < DNS_PACKET_QDCOUNT(p); i++)
                ASSERT_OK(dns_packet_read_key(p, NULL, NULL, NULL));

        unsigned n[] = { DNS_PACKET_ANCOUNT(p), DNS_PACKET_NSCOUNT(p), DNS_PACKET_ARCOUNT(p) };
        FOREACH_ELEMENT(count, n) {
                if (count != n)
                        ASSERT_NOT_NULL(strextend(&layout, "|"));

                for (unsigned i = 0; i < *count; i++) {
                        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
                        uint8_t fill;

                        log_debug("Reading RR at offset %zu of %zu", p->rindex, p->size);
                        ASSERT_OK(dns_packet_read_rr(p, &rr, NULL, NULL));

                        if (rr->key->type == DNS_TYPE_OPT) {
                                ASSERT_NOT_NULL(strextend(&layout, "O"));
                                continue;
                        }

                        ASSERT_EQ(rr->key->type, DNS_TYPE_DNSKEY);
                        ASSERT_EQ(rr->dnskey.key_size, DNSKEY_KEY_SIZE);
                        fill = *(uint8_t*) rr->dnskey.key;
                        ASSERT_TRUE(memeqbyte(fill, rr->dnskey.key, rr->dnskey.key_size));
                        ASSERT_OK(strextendf(&layout, "%c", fill));
                }
        }
        ASSERT_EQ(p->rindex, p->size);

        ASSERT_OK(dns_packet_extract(p));
        ASSERT_EQ(DNS_PACKET_RRCOUNT(p), dns_answer_size(p->answer) + !!p->opt);

        *ret_parsed = TAKE_PTR(p);
        *ret_layout = TAKE_PTR(layout);
}

static void assert_only_tc_added(DnsPacket *reply, DnsPacket *original) {
        ASSERT_EQ(be16toh(DNS_PACKET_HEADER(reply)->flags),
                  be16toh(DNS_PACKET_HEADER(original)->flags) | DNS_PACKET_FLAG_TC);
}

TEST(patch_bypass_reply_packet_truncated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_free_ char *layout = NULL;

        /* An oversized upstream reply (e.g. received via TCP or from the cache) is proxied back to a UDP
         * client that advertised a 512-byte EDNS0 payload size. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(key, 512, &request);
        make_upstream_reply(key, "abcde||O", &original);
        ASSERT_EQ(original->size, 1112U);

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        ASSERT_EQ(DNS_PACKET_ID(reply), DNS_PACKET_ID(request));
        assert_only_tc_added(reply, original);

        /* Two DNSKEY RRs fit, with the OPT RR moved behind them */
        ASSERT_EQ(reply->size, 464U);
        parse_reply(reply, &parsed, &layout);
        ASSERT_EQ(DNS_PACKET_QDCOUNT(parsed), 1U);
        ASSERT_STREQ(layout, "ab||O");
        ASSERT_EQ(parsed->opt->key->class, ADVERTISE_DATAGRAM_SIZE_MAX);
}

TEST(patch_bypass_reply_packet_truncated_large_opt) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_free_ char *nsid = NULL, *layout = NULL;

        /* The upstream OPT RR doesn't even fit right behind the question. The reply must still carry an OPT
         * RR with the UDP payload size, extended RCODE and flags. Only the options may be dropped. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(key, 512, &request);

        /* Replace the OPT RR by one with DO, an extended RCODE and a large NSID option, making it 495 bytes,
         * which doesn't fit behind the 21 bytes of header and question. */
        make_upstream_reply(key, "abcde||O", &original);
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
        ASSERT_EQ(original->size, 1596U);

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        assert_only_tc_added(reply, original);

        /* Only the 11 byte fixed part of the OPT RR is retained, which leaves room for two DNSKEY RRs */
        ASSERT_EQ(reply->size, 464U);
        parse_reply(reply, &parsed, &layout);
        ASSERT_STREQ(layout, "ab||O");
        ASSERT_EQ(parsed->opt->opt.data_size, 0U);
        ASSERT_EQ(parsed->opt->key->class, ADVERTISE_DATAGRAM_SIZE_MAX);
        ASSERT_TRUE(dns_packet_do(parsed));
        ASSERT_EQ(dns_packet_rcode(parsed), DNS_RCODE_BADCOOKIE);
}

TEST(patch_bypass_reply_packet_truncated_no_edns) {
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_free_ char *layout = NULL;

        /* A client that didn't use EDNS0 might still get an upstream packet with an OPT RR, e.g. one cached
         * from an earlier lookup with DO. Its truncated reply must not gain an OPT RR. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(key, /* max_udp_size= */ 0, &request);
        make_upstream_reply(key, "abcde||O", &original);

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        assert_only_tc_added(reply, original);

        ASSERT_EQ(reply->size, 453U);
        parse_reply(reply, &parsed, &layout);
        ASSERT_STREQ(layout, "ab||");
        ASSERT_NULL(parsed->opt);
}

TEST(patch_bypass_reply_packet_truncated_sections) {
        static const struct {
                unsigned max_udp_size;
                size_t size;
                const char *layout;
        } table[] = {
                /* Cut in the answer section */
                {  512U,  464U, "ab||O"     },
                /* Cut in the authority section */
                {  900U,  896U, "abc|n|O"   },
                /* Cut in front of the first additional RR, the OPT RR is moved up to the cut */
                { 1200U, 1112U, "abc|no|O"  },
                /* Cut behind the OPT RR, which stays in place */
                { 1400U, 1328U, "abc|no|xO" },
        };
        _cleanup_(dns_packet_unrefp) DnsPacket *original = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        /* All three sections, with the OPT RR in the middle of the additional section */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_upstream_reply(key, "abc|no|xOy", &original);
        ASSERT_EQ(original->size, 1544U);

        FOREACH_ELEMENT(t, table) {
                _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *reply = NULL, *parsed = NULL;
                _cleanup_free_ char *layout = NULL;

                log_debug("Client payload size %u", t->max_udp_size);

                make_request(key, t->max_udp_size, &request);

                ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                             /* validated= */ true,
                                                             /* authenticated= */ false));

                assert_only_tc_added(reply, original);

                ASSERT_EQ(reply->size, t->size);
                parse_reply(reply, &parsed, &layout);
                ASSERT_STREQ(layout, t->layout);
                ASSERT_EQ(parsed->opt->key->class, ADVERTISE_DATAGRAM_SIZE_MAX);
        }
}

TEST(patch_bypass_reply_packet_trailing_garbage) {
        static const uint8_t garbage[64] = {};
        _cleanup_(dns_packet_unrefp) DnsPacket *request = NULL, *original = NULL, *reply = NULL,
                *parsed = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_free_ char *layout = NULL;

        /* All RRs fit, but trailing garbage pushes the upstream packet over the limit. The garbage must not
         * end up in the reply. As dns_packet_extract() ignores the OPT RR of such a packet, it is retained
         * like any other RR. */

        ASSERT_NOT_NULL(key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_DNSKEY, "org"));

        make_request(key, 512, &request);
        make_upstream_reply(key, "ab||O", &original);
        ASSERT_OK(dns_packet_append_blob(original, garbage, sizeof(garbage), NULL));
        ASSERT_EQ(original->size, 528U);

        ASSERT_OK(dns_stub_patch_bypass_reply_packet(&reply, original, request,
                                                     /* validated= */ true,
                                                     /* authenticated= */ false));

        assert_only_tc_added(reply, original);

        ASSERT_EQ(reply->size, 464U);
        parse_reply(reply, &parsed, &layout);
        ASSERT_STREQ(layout, "ab||O");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
