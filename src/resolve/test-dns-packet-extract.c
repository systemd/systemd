/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-type.h"
#include "resolved-dns-packet.h"
#include "resolved-dns-rr.h"

#include "log.h"
#include "tests.h"

#define BIT_QR (1 << 7)
#define BIT_AA (1 << 2)
#define BIT_TC (1 << 1)
#define BIT_RD (1 << 0)

#define BIT_RA (1 << 7)
#define BIT_AD (1 << 5)
#define BIT_CD (1 << 4)

/* ================================================================
 * packet header
 * ================================================================ */

TEST(packet_header_query_basic) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     0x00, 0x00,
                0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 1);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

TEST(packet_header_query_status_recursion_desired) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     (2 << 3) | BIT_RD, 0x00,
                0x01, 0x53,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 2);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 1);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 339);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

TEST(packet_header_reply_authoritative) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                0x00, 0x03,     0x00, 0x04,     0x00, 0x00,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 1);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), DNS_RCODE_SUCCESS);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 3);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 4);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

TEST(packet_header_reply_nxdomain) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                0x00, 0x01,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 1);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), DNS_RCODE_NXDOMAIN);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 1);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 1);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

TEST(packet_header_reply_recursive_non_authoritative) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     BIT_QR | BIT_RD, BIT_RA | DNS_RCODE_SUCCESS,
                0x05, 0x03,     0x0e, 0x04,     0x00, 0x00,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 1);

        ASSERT_EQ(DNS_PACKET_RA(packet), 1);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), DNS_RCODE_SUCCESS);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 1283);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 3588);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

TEST(packet_header_reply_delegate) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     BIT_QR, DNS_RCODE_SUCCESS,
                0x00, 0x01,     0x00, 0x00,     0x09, 0x0d,     0x0c, 0x1a
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66u);

        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), DNS_RCODE_SUCCESS);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 1);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 2317);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 3098);
}

TEST(packet_header_reply_dnssec_bits) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                0x00, 0x42,     BIT_QR | BIT_AA, BIT_AD | BIT_CD | DNS_RCODE_SUCCESS,
                0x00, 0x03,     0x00, 0x04,     0x00, 0x00,     0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_EQ(be16toh(DNS_PACKET_ID(packet)), 66);

        ASSERT_EQ(DNS_PACKET_QR(packet), 1);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 1);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 1);
        ASSERT_EQ(DNS_PACKET_CD(packet), 1);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), DNS_RCODE_SUCCESS);

        ASSERT_EQ(DNS_PACKET_QDCOUNT(packet), 3);
        ASSERT_EQ(DNS_PACKET_ANCOUNT(packet), 4);
        ASSERT_EQ(DNS_PACKET_NSCOUNT(packet), 0);
        ASSERT_EQ(DNS_PACKET_ARCOUNT(packet), 0);
}

/* ================================================================
 * queries
 * ================================================================ */

TEST(packet_query_single) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x04, 'm', 'a', 'i', 'l',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* MX */        0x00, 0x0f,
        /* ANY */       0x00, 0xff
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 2u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

TEST(packet_query_multi_compressed_domain_1) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x04, 'm', 'a', 'i', 'l',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0xc0, 0x18,
        /* MX */        0x00, 0x0f,
        /* ANY */       0x00, 0xff
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 2u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

TEST(packet_query_multi_compressed_domain_2) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01,

        /* name */      0x04, 'm', 'a', 'i', 'l',
                        0xc0, 0x10,
        /* MX */        0x00, 0x0f,
        /* ANY */       0x00, 0xff
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 2u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

/* ================================================================
 * reply: A
 * ================================================================ */

static void check_answer_contains(DnsPacket *packet, DnsResourceRecord *rr, DnsAnswerFlags flags) {
        DnsAnswerFlags key_flags;

        ASSERT_TRUE(dns_answer_contains(packet->answer, rr));

        ASSERT_TRUE(dns_answer_match_key(packet->answer, rr->key, &key_flags));
        ASSERT_EQ(key_flags, flags);
}

TEST(packet_reply_a_single) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

/* ================================================================
 * reply: CNAME, compression
 * ================================================================ */

static void check_cname_reply_compression(const uint8_t *data, size_t len) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        dns_packet_truncate(packet, 0);

        ASSERT_OK(dns_packet_append_blob(packet, data, len, NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        rr->ttl = 3600;
        rr->cname.name = strdup("example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_cname_uncompressed) {
        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x01,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* CNAME */     0x00, 0x05,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x0d,
        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        check_cname_reply_compression(data, sizeof(data));
}

TEST(packet_reply_cname_partial_compression) {
        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x01,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0xc0, 0x18,
        /* CNAME */     0x00, 0x05,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x02,
        /* name */      0xc0, 0x25,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0xc0, 0x2d,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        check_cname_reply_compression(data, sizeof(data));
}

TEST(packet_reply_cname_full_compression) {
        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x01,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0xc0, 0x0c,
        /* CNAME */     0x00, 0x05,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x02,
        /* name */      0xc0, 0x10,

        /* name */      0xc0, 0x10,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        check_cname_reply_compression(data, sizeof(data));
}

DEFINE_TEST_MAIN(LOG_DEBUG)
