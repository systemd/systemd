/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-dns-packet.h"

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

DEFINE_TEST_MAIN(LOG_DEBUG)
