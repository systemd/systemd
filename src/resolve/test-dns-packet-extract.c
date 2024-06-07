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

TEST(packet_query_single_missing_bytes) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_unknown_type) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_bad_type) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_long_label) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_extra_bytes) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_single_domain_overflow) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        ASSERT_TRUE(dns_question_contains_key(packet->question, key));
}

TEST(packet_query_bad_compression) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_a_zero_ip) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_a_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xc0a8017f);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        rr->ttl = 3600;
        rr->a.in_addr.s_addr = htobe32(0xa9fe0100);

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_ANSWER | DNS_ANSWER_CACHEABLE);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_a_bad_rdata_size) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        rr->ttl = 3600;
        rr->ns.name = strdup("ns1.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_ns_multi) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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
        rr->ttl = 3600;
        rr->ns.name = strdup("ns1.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        rr->ttl = 3600;
        rr->ns.name = strdup("ns2.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_NS, "example.com");
        rr->ttl = 3600;
        rr->ns.name = strdup("ns3.example.com");

        check_answer_contains(packet, rr, DNS_ANSWER_SECTION_AUTHORITY);
        dns_resource_record_unref(rr);
}

TEST(packet_reply_ns_domain_underflows_rdata) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

/* ================================================================
 * reply: SOA
 * ================================================================ */

TEST(packet_reply_soa_basic) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceRecord *rr = NULL;

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

        dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
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

DEFINE_TEST_MAIN(LOG_DEBUG)
