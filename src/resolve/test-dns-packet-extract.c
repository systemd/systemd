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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

TEST(packet_query_multi_compressed_domain_1) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

TEST(packet_query_multi_compressed_domain_2) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
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
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_MX, "mail.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);
}

TEST(packet_query_single_missing_bytes) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01
                        /* missing class */
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_single_unknown_class) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* ??? */       0x00, 0x20
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(32, DNS_TYPE_A, "com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_unknown_type) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* ??? */       0x00, 0x50,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, 80, "com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_bad_type) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* OPT */       0x00, 0x29,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_single_long_domain) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x10, 'a', 'b', 's', 'o', 'r', 'p', 't', 'i', 'v', 'e', 'n', 'e', 's', 's', 'e', 's',
                        0x10, 'c', 'a', 'l', 'l', 'i', 'g', 'r', 'a', 'p', 'h', 'i', 'c', 'a', 'l', 'l', 'y',
                        0x10, 'd', 'e', 'a', 'c', 'i', 'd', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 's',
                        0x10, 'e', 'c', 'o', 'p', 'h', 'y', 's', 'i', 'o', 'l', 'o', 'g', 'i', 'c', 'a', 'l',
                        0x10, 'f', 'a', 'l', 's', 'i', 'f', 'i', 'a', 'b', 'i', 'l', 'i', 't', 'i', 'e', 's',
                        0x10, 'h', 'e', 't', 'e', 'r', 'o', 'c', 'h', 'r', 'o', 'm', 'a', 't', 'i', 's', 'm',
                        0x10, 'i', 'c', 'o', 's', 'i', 't', 'e', 't', 'r', 'a', 'h', 'e', 'd', 'r', 'o', 'n',
                        0x10, 'j', 'o', 'u', 'r', 'n', 'a', 'l', 'i', 's', 't', 'i', 'c', 'a', 'l', 'l', 'y',
                        0x10, 'k', 'i', 'n', 'a', 'e', 's', 't', 'h', 'e', 't', 'i', 'c', 'a', 'l', 'l', 'y',
                        0x10, 'l', 'a', 'c', 't', 'o', 'v', 'e', 'g', 'e', 't', 'a', 'r', 'i', 'a', 'n', 's',
                        0x10, 'm', 'i', 's', 'i', 'n', 't', 'e', 'r', 'p', 'r', 'e', 't', 'a', 'b', 'l', 'e',
                        0x10, 'n', 'i', 't', 'r', 'o', 's', 'y', 'l', 's', 'u', 'l', 'f', 'u', 'r', 'i', 'c',
                        0x10, 'o', 'b', 'j', 'e', 'c', 't', 'l', 'e', 's', 's', 'n', 'e', 's', 's', 'e', 's',
                        0x10, 'p', 'a', 'r', 't', 'r', 'i', 'd', 'g', 'e', 'b', 'e', 'r', 'r', 'i', 'e', 's',
                        0x10, 'r', 'e', 'a', 's', 'o', 'n', 'l', 'e', 's', 's', 'n', 'e', 's', 's', 'e', 's',
                        0x10, 's', 'e', 'm', 'i', 'p', 'a', 't', 'h', 'o', 'l', 'o', 'g', 'i', 'c', 'a', 'l',
                        0x10, 't', 'o', 'm', 'f', 'o', 'o', 'l', 'i', 's', 'h', 'n', 'e', 's', 's', 'e', 's',
                        0x10, 'u', 'n', 'd', 'e', 'r', 'c', 'a', 'p', 'i', 't', 'a', 'l', 'i', 'z', 'e', 'd',
                        0x10, 'v', 'e', 'c', 't', 'o', 'r', 'c', 'a', 'r', 'd', 'i', 'o', 'g', 'r', 'a', 'm',
                        0x10, 'w', 'e', 'a', 't', 'h', 'e', 'r', 'p', 'r', 'o', 'o', 'f', 'n', 'e', 's', 's',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A,
                "absorptivenesses.calligraphically.deacidifications.ecophysiological."
                "falsifiabilities.heterochromatism.icositetrahedron.journalistically."
                "kinaesthetically.lactovegetarians.misinterpretable.nitrosylsulfuric."
                "objectlessnesses.partridgeberries.reasonlessnesses.semipathological."
                "tomfoolishnesses.undercapitalized.vectorcardiogram.weatherproofness");

        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_long_label) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x48,   'a', '-', 'd', 'o', 'm', 'a', 'i', 'n', '-',
                                'n', 'a', 'm', 'e', '-', 'l', 'a', 'b', 'e', 'l', '-',
                                't', 'h', 'a', 't', '-', 'g', 'o', 'e', 's', '-',
                                'p', 'a', 's', 't', '-', 't', 'h', 'e', '-',
                                'l', 'e', 'n', 'g', 't', 'h', '-', 'l', 'i', 'm', 'i', 't', '-',
                                'o', 'f', '-', 's', 'i', 'x', 't', 'y', '-',
                                't', 'h', 'r', 'e', 'e', '-', 'b', 'y', 't', 'e', 's',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_single_invalid_label) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, '9', '_', '?',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "9_?");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_extra_bytes) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* extra */     0x04, 'm', 'a', 'i', 'l'
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_domain_overflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'm', 'a', 'i', 'l',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_single_domain_underflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x04, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_single_domain_missing_root) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        /* missing 0x00 */
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_missing_question) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_extra_question) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x03, 'o', 'r', 'g',
                        0x00,
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_bad_compression) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0xc0, 0x0b,     /* points 1 byte before start of "com" */
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_bad_compression_2) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0xc0, 0x0d,     /* points 1 byte after start of "com" */
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_bad_compression_3) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0xc0, 0x0c,
                        0x00,           /* extra null terminator */
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_bad_compression_4) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0xc0, 0x80,     /* points past end of message */
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_bad_compression_5) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     0x00, 0x00,
                        0x00, 0x02,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0xc0, 0x12,     /* points at "com" in next question */
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,

        /* name */      0x03, 'c', 'o', 'm',
                        0x00,
        /* AAAA */      0x00, 0x1c,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_query_bad_compression_6) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x2a,     0x01, 0x00,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0xc0, 0x0c,     /* points at the current name */
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* ================================================================
 * reply: bad keys
 * ================================================================ */

TEST(packet_reply_cannot_use_class_any) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* ANY */       0x00, 0xff,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_cannot_use_type_any) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* ANY */       0x00, 0xff,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
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
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
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

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
}

TEST(packet_reply_a_zero_ip) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0x00, 0x00, 0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
}

TEST(packet_reply_a_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f,

        /* name */      0xc0, 0x0c,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xa9, 0xfe, 0x01, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fe0100);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_a_bad_rdata_size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x05,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f, 0x99
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_a_rdata_truncated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01        /* missing last byte */
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* ================================================================
 * reply: NS
 * ================================================================ */

TEST(packet_reply_ns_single) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x06,
        /* name */      0x03, 'n', 's', '1',
                        0xc0, 0x0c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->ns.name = strdup("ns1.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_ns_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x03,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x06,
        /* name */      0x03, 'n', 's', '1',
                        0xc0, 0x0c,

        /* name */      0xc0, 0x0c,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x06,
        /* name */      0x03, 'n', 's', '2',
                        0xc0, 0x0c,

        /* name */      0xc0, 0x0c,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x06,
        /* name */      0x03, 'n', 's', '3',
                        0xc0, 0x0c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 3u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->ns.name = strdup("ns1.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->ns.name = strdup("ns2.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->ns.name = strdup("ns3.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_ns_domain_underflows_rdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x12,
        /* name */      0x03, 'n', 's', '1',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_ns_domain_overflows_rdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x06,
        /* name */      0x03, 'n', 's', '1',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_ns_domain_overflows_rdata_compressed) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x05,
        /* name */      0x03, 'n', 's', '1',
                        0xc0, 0x0c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_ns_domain_unterminated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* NS */        0x00, 0x02,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x10,
        /* name */      0x03, 'n', 's', '1',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm'
                        /* missing 0x00 */
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* ================================================================
 * reply: CNAME with A, compression
 * ================================================================ */

static void check_cname_reply_compression(const uint8_t *data, size_t len) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        ASSERT_OK(dns_packet_append_blob(packet, data, len, NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 1u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
        dns_resource_key_unref(key);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->cname.name = strdup("example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        ASSERT_NOT_NULL(rr);
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

/* ================================================================
 * reply: SOA
 * ================================================================ */

TEST(packet_reply_soa_basic) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x27,
        /* mname */     0x03, 'n', 's', '0',
                        0xc0, 0x0c,
        /* rname */     0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r',
                        0xc0, 0x0c,
        /* serial */    0x78, 0x85, 0x75, 0x2e,
        /* refresh */   0x00, 0x02, 0xa3, 0x00,
        /* retry */     0x00, 0x00, 0x00, 0xb4,
        /* expire */    0x00, 0x24, 0xea, 0x00,
        /* minimum */   0x00, 0x00, 0x00, 0x3c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->soa.mname = strdup("ns0.example.com");
        rr->soa.rname = strdup("hostmaster.example.com");
        rr->soa.serial = 2022012206;
        rr->soa.refresh = 172800;
        rr->soa.retry = 180;
        rr->soa.expire = 2419200;
        rr->soa.minimum = 60;

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_soa_rdata_overflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x26,
        /* mname */     0x03, 'n', 's', '0',
                        0xc0, 0x0c,
        /* rname */     0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r',
                        0xc0, 0x0c,
        /* serial */    0x78, 0x85, 0x75, 0x2e,
        /* refresh */   0x00, 0x02, 0xa3, 0x00,
        /* retry */     0x00, 0x00, 0x00, 0xb4,
        /* expire */    0x00, 0x24, 0xea, 0x00,
        /* minimum */   0x00, 0x00, 0x00, 0x3c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_soa_rdata_underminated_domain) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x31,
        /* mname */     0x03, 'n', 's', '0',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        /* missing 0x00 */
        /* rname */     0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r',
                        0xc0, 0x0c,
        /* serial */    0x78, 0x85, 0x75, 0x2e,
        /* refresh */   0x00, 0x02, 0xa3, 0x00,
        /* retry */     0x00, 0x00, 0x00, 0xb4,
        /* expire */    0x00, 0x24, 0xea, 0x00,
        /* minimum */   0x00, 0x00, 0x00, 0x3c
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_soa_rdata_missing_field) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x23,
        /* mname */     0x03, 'n', 's', '0',
                        0xc0, 0x0c,
        /* rname */     0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r',
                        0xc0, 0x0c,
        /* serial */    0x78, 0x85, 0x75, 0x2e,
        /* refresh */   0x00, 0x02, 0xa3, 0x00,
        /* retry */     0x00, 0x00, 0x00, 0xb4,
        /* expire */    0x00, 0x24, 0xea, 0x00
        /* minimum (missing) */
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_soa_rdata_partial_final_field) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_NXDOMAIN,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x01,     0x00, 0x00,

        /* name */      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x26,
        /* mname */     0x03, 'n', 's', '0',
                        0xc0, 0x0c,
        /* rname */     0x0a, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r',
                        0xc0, 0x0c,
        /* serial */    0x78, 0x85, 0x75, 0x2e,
        /* refresh */   0x00, 0x02, 0xa3, 0x00,
        /* retry */     0x00, 0x00, 0x00, 0xb4,
        /* expire */    0x00, 0x24, 0xea, 0x00,
        /* minimum */   0x00, 0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* ================================================================
 * reply: SRV
 * ================================================================ */

TEST(packet_reply_srv_with_a) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x05, '_', 'l', 'd', 'a', 'p',
                        0x04, '_', 't', 'c', 'p',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SRV */       0x00, 0x21,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x19,
        /* priority */  0x43, 0x21,
        /* weight */    0x65, 0x78,
        /* port */      0x01, 0x85,
        /* name */      0x05, 'c', 'l', 'o', 'u', 'd',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,

        /* name */      0xc0, 0x34,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "_ldap._tcp.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->srv.priority = 17185;
        rr->srv.weight = 25976;
        rr->srv.port = 389;
        rr->srv.name = strdup("cloud.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "cloud.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

/* we allow compression of the SRV target field even though RFC 2782 advises against it */

TEST(packet_reply_srv_compression) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x05, '_', 'l', 'd', 'a', 'p',
                        0x04, '_', 't', 'c', 'p',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SRV */       0x00, 0x21,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x0e,
        /* priority */  0x00, 0x0a,
        /* weight */    0x00, 0x05,
        /* port */      0x01, 0x85,
        /* name */      0x05, 'c', 'l', 'o', 'u', 'd',
                        0xc0, 0x17,

        /* name */      0xc0, 0x34,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "_ldap._tcp.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->srv.priority = 10;
        rr->srv.weight = 5;
        rr->srv.port = 389;
        rr->srv.name = strdup("cloud.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "cloud.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_srv_allow_non_srv_names) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x01,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SRV */       0x00, 0x21,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x0e,
        /* priority */  0x00, 0x0a,
        /* weight */    0x00, 0x05,
        /* port */      0x01, 0x85,
        /* name */      0x05, 'c', 'l', 'o', 'u', 'd',
                        0xc0, 0x10
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->srv.priority = 10;
        rr->srv.weight = 5;
        rr->srv.port = 389;
        rr->srv.name = strdup("cloud.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

/* ================================================================
 * reply: RRSIG
 * ================================================================ */

TEST(packet_reply_rrsig_for_a) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f,

        /* name */      0xc0, 0x0c,
        /* RRSIG */     0x00, 0x2e,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x27,
        /* type */      0x00, 0x01,
        /* algo */      0x04,
        /* labels */    0x03,
        /* orig ttl */  0x00, 0x00, 0x0e, 0x10,
        /* expiry */    0x66, 0x8a, 0xa1, 0x57,
        /* inception */ 0x66, 0x63, 0x14, 0x57,
        /* key tag */   0x12, 0x34,
        /* signer */    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* signature */ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        const uint8_t signature[] = {
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 2u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_RRSIG, "www.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->rrsig.type_covered = DNS_TYPE_A;
        rr->rrsig.algorithm = DNSSEC_ALGORITHM_ECC;
        rr->rrsig.labels = 3;
        rr->rrsig.original_ttl = 3600;
        rr->rrsig.expiration = 1720361303;
        rr->rrsig.inception = 1717769303;
        rr->rrsig.key_tag = 0x1234;
        rr->rrsig.signer = strdup("example.com");

        rr->rrsig.signature_size = sizeof(signature);
        rr->rrsig.signature = memdup(signature, rr->rrsig.signature_size);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_rrsig_no_compression) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f,

        /* name */      0xc0, 0x0c,
        /* RRSIG */     0x00, 0x2e,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1c,
        /* type */      0x00, 0x01,
        /* algo */      0x04,
        /* labels */    0x03,
        /* orig ttl */  0x00, 0x00, 0x0e, 0x10,
        /* expiry */    0x66, 0x8a, 0xa1, 0x57,
        /* inception */ 0x66, 0x63, 0x14, 0x57,
        /* key tag */   0x12, 0x34,
        /* signer */    0xc0, 0x10,
        /* signature */ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_rrsig_signature_underflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f,

        /* name */      0xc0, 0x0c,
        /* RRSIG */     0x00, 0x2e,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x28,
        /* type */      0x00, 0x01,
        /* algo */      0x04,
        /* labels */    0x03,
        /* orig ttl */  0x00, 0x00, 0x0e, 0x10,
        /* expiry */    0x66, 0x8a, 0xa1, 0x57,
        /* inception */ 0x66, 0x63, 0x14, 0x57,
        /* key tag */   0x12, 0x34,
        /* signer */    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* signature */ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_rrsig_signer_overflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x02,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x04,
        /* ip */        0xc0, 0xa8, 0x01, 0x7f,

        /* name */      0xc0, 0x0c,
        /* RRSIG */     0x00, 0x2e,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1e,
        /* type */      0x00, 0x01,
        /* algo */      0x04,
        /* labels */    0x03,
        /* orig ttl */  0x00, 0x00, 0x0e, 0x10,
        /* expiry */    0x66, 0x8a, 0xa1, 0x57,
        /* inception */ 0x66, 0x63, 0x14, 0x57,
        /* key tag */   0x12, 0x34,
        /* signer */    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* signature */ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* ================================================================
 * reply: SVCB/HTTPS
 * ================================================================ */

static DnsSvcParam* add_svcb_param(DnsResourceRecord *rr, uint16_t key, const char *value, size_t len) {
        DnsSvcParam *param = calloc(1, offsetof(DnsSvcParam, value) + len);
        ASSERT_NOT_NULL(param);

        param->key = key;
        param->length = len;

        if (value != NULL)
                memcpy(param->value, value, len);

        LIST_APPEND(params, rr->svcb.params, param);
        return param;
}

TEST(packet_reply_svcb_alias_mode) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x14,
        /* priority */  0x00, 0x00,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->svcb.priority = 0;
        rr->svcb.target_name = strdup("sock.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_svcb_compressed_target) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x09,
        /* priority */  0x00, 0x00,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0xc0, 0x16
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

/* RFC 9460 says that alias-mode RRs SHOULD NOT have the same owner and target.
 * We accept this when parsing messages. */

TEST(packet_reply_svcb_alias_mode_same_owner_and_target) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x14,
        /* priority */  0x00, 0x00,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "sock.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->svcb.priority = 0;
        rr->svcb.target_name = strdup("sock.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

/* RFC 9460 says that recipients MUST ignore any params presented in alias mode RRs. We parse them out of the
 * message and their handling is down to further business logic, rather than rejecting such RRs in the
 * parser. */

TEST(packet_reply_svcb_alias_mode_with_param) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x18,
        /* priority */  0x00, 0x00,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* no-deflt */  0x00, 0x02,
                        0x00, 0x00,
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->svcb.priority = 0;
        rr->svcb.target_name = strdup("sock.example.com");

        add_svcb_param(rr, DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN, NULL, 0);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_svcb_service_mode) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;
        DnsSvcParam *param = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x54,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* mandatory */ 0x00, 0x00,
                        0x00, 0x04,
                        0x00, 0x01, 0x00, 0x03,
        /* alpn */      0x00, 0x01,
                        0x00, 0x0a,
                        0x09, 'w', 'e', 'b', 's', 'o', 'c', 'k', 'e', 't',
        /* no-deflt */  0x00, 0x02,
                        0x00, 0x00,
        /* port */      0x00, 0x03,
                        0x00, 0x02,
                        0x01, 0xbb,
        /* ipv4hint */  0x00, 0x04,
                        0x00, 0x08,
                        0x72, 0x84, 0xfd, 0x3a,
                        0x48, 0xbc, 0xc7, 0xc0,
        /* ipv6hint */  0x00, 0x06,
                        0x00, 0x10,
                        0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35,
                        0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e, 0x60, 0xbb
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SVCB, "_443._wss.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->svcb.priority = 2;
        rr->svcb.target_name = strdup("sock.example.com");

        add_svcb_param(rr, DNS_SVC_PARAM_KEY_MANDATORY, "\x00\x01\x00\x03", 4);
        add_svcb_param(rr, DNS_SVC_PARAM_KEY_ALPN, "\x09websocket", 10);
        add_svcb_param(rr, DNS_SVC_PARAM_KEY_NO_DEFAULT_ALPN, "", 0);
        add_svcb_param(rr, DNS_SVC_PARAM_KEY_PORT, "\x01\xbb", 2);

        param = add_svcb_param(rr, DNS_SVC_PARAM_KEY_IPV4HINT, NULL, 2 * sizeof(struct in_addr));
        param->value_in_addr[0].s_addr = htobe32(0x7284fd3a);
        param->value_in_addr[1].s_addr = htobe32(0x48bcc7c0);

        param = add_svcb_param(rr, DNS_SVC_PARAM_KEY_IPV6HINT, NULL, sizeof(struct in6_addr));
        param->value_in6_addr[0] = (struct in6_addr) { .s6_addr = { 0xf2, 0x34, 0x32, 0x2e, 0xb8, 0x25, 0x38, 0x35, 0x2f, 0xd7, 0xdb, 0x7b, 0x28, 0x7e, 0x60, 0xbb } };

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

/* RFC 9460 says that clients MUST ignore any param keys that they do not recognise. We allow such keys to be
 * parsed; handling of them is down to later business logic. */

TEST(packet_reply_svcb_service_mode_unknown_param) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* HTTPS */     0x00, 0x41,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x18,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* unknown */   0x00, 0x99,
                        0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_OK(dns_packet_extract(packet));
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 1u);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_HTTPS, "_443._wss.example.com");
        ASSERT_NOT_NULL(rr);
        rr->ttl = 3600;
        rr->svcb.priority = 2;
        rr->svcb.target_name = strdup("sock.example.com");

        add_svcb_param(rr, 153, NULL, 0);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ADDITIONAL);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_svcb_service_mode_duplicate_key) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x20,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* port */      0x00, 0x03,
                        0x00, 0x02,
                        0x01, 0xbb,
        /* port */      0x00, 0x03,
                        0x00, 0x02,
                        0x01, 0xbc,
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_key_bad_order) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1e,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* port */      0x00, 0x03,
                        0x00, 0x02,
                        0x01, 0xbb,
        /* no-deflt */  0x00, 0x02,
                        0x00, 0x00
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_alpn_too_long) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x20,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* alpn */      0x00, 0x01,
                        0x00, 0x07,
                        0x04, 'h', 't', 't', 'p',
                        0x02, 'w', 's'
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_alpn_too_short) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x20,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* alpn */      0x00, 0x01,
                        0x00, 0x09,
                        0x04, 'h', 't', 't', 'p',
                        0x02, 'w', 's'
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EMSGSIZE);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_valid_alpn_overflows_rdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1f,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* alpn */      0x00, 0x01,
                        0x00, 0x08,
                        0x04, 'h', 't', 't', 'p',
                        0x02, 'w', 's'
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_valid_alpn_and_port_overflows_rdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x25,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* alpn */      0x00, 0x01,
                        0x00, 0x08,
                        0x04, 'h', 't', 't', 'p',
                        0x02, 'w', 's',
        /* port */      0x00, 0x03,
                        0x00, 0x02,
                        0x01, 0xbb
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_bad_no_default_alpn) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x19,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* no-deflt */  0x00, 0x02,
                        0x00, 0x01,
                        0x0a
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_port_too_long) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1b,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* port */      0x00, 0x03,
                        0x00, 0x03,
                        0x01, 0xbb, 0xff
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_port_too_short) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x19,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* port */      0x00, 0x03,
                        0x00, 0x01,
                        0xbb
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_bad_ipv4hint) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x1b,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* ipv4hint */  0x00, 0x04,
                        0x00, 0x03,
                        0x2f, 0x47, 0x34
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

TEST(packet_reply_svcb_service_mode_bad_ipv6hint) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_truncate(packet, 0);

        const uint8_t data[] = {
                        0x00, 0x42,     BIT_QR | BIT_AA, DNS_RCODE_SUCCESS,
                        0x00, 0x00,     0x00, 0x00,     0x00, 0x00,     0x00, 0x01,

        /* name */      0x04, '_', '4', '4', '3',
                        0x04, '_', 'w', 's', 's',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SVCB */      0x00, 0x40,
        /* IN */        0x00, 0x01,
        /* ttl */       0x00, 0x00, 0x0e, 0x10,
        /* rdata */     0x00, 0x27,
        /* priority */  0x00, 0x02,
        /* target */    0x04, 's', 'o', 'c', 'k',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* ipv6hint */  0x00, 0x06,
                        0x00, 0x0f,
                        0x09, 0x36, 0xba, 0x5d, 0x17, 0x42, 0x47, 0xa2,
                        0x14, 0xcc, 0x77, 0x67, 0x51, 0x68, 0xef
        };

        ASSERT_OK(dns_packet_append_blob(packet, data, sizeof(data), NULL));

        ASSERT_ERROR(dns_packet_extract(packet), EBADMSG);
        ASSERT_EQ(dns_question_size(packet->question), 0u);
        ASSERT_EQ(dns_answer_size(packet->answer), 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
