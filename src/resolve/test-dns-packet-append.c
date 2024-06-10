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
 * dns_packet_set_flags()
 * ================================================================ */

TEST(packet_set_flags_dns_checking_enabled) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_set_flags(packet, /* dnssec_checking_disabled= */ false, /* truncated= */ false);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 1);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);
}

TEST(packet_set_flags_dns_checking_disabled) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_set_flags(packet, /* dnssec_checking_disabled= */ true, /* truncated= */ false);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 1);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 1);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);
}

TEST(packet_set_flags_llmnr) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_LLMNR, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_set_flags(packet, /* dnssec_checking_disabled= */ true, /* truncated= */ false);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);
}

TEST(packet_set_flags_mdns_not_truncated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_MDNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_set_flags(packet, /* dnssec_checking_disabled= */ true, /* truncated= */ false);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);
}

TEST(packet_set_flags_mdns_truncated) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_MDNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);
        dns_packet_set_flags(packet, /* dnssec_checking_disabled= */ true, /* truncated= */ true);

        ASSERT_EQ(DNS_PACKET_QR(packet), 0);
        ASSERT_EQ(DNS_PACKET_OPCODE(packet), 0);
        ASSERT_EQ(DNS_PACKET_AA(packet), 0);
        ASSERT_EQ(DNS_PACKET_TC(packet), 1);
        ASSERT_EQ(DNS_PACKET_RD(packet), 0);

        ASSERT_EQ(DNS_PACKET_RA(packet), 0);
        ASSERT_EQ(DNS_PACKET_AD(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
        ASSERT_EQ(DNS_PACKET_RCODE(packet), 0);
}

/* ================================================================
 * dns_packet_new_query()
 * ================================================================ */

TEST(packet_new_query_checking_enabled) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, false));
        ASSERT_NOT_NULL(packet);

        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 0);
}

TEST(packet_new_query_checking_disabled) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;

        ASSERT_OK(dns_packet_new_query(&packet, DNS_PROTOCOL_DNS, 0, true));
        ASSERT_NOT_NULL(packet);

        ASSERT_EQ(DNS_PACKET_TC(packet), 0);
        ASSERT_EQ(DNS_PACKET_CD(packet), 1);
}

/* ================================================================
 * dns_packet_append_key()
 * ================================================================ */

TEST(packet_append_key_single_a) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);

        DNS_PACKET_ID(packet) = htobe16(42);
        DNS_PACKET_HEADER(packet)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0, 0, 0, 0, 1, 0, 0, 0, DNS_RCODE_SUCCESS));
        DNS_PACKET_HEADER(packet)->qdcount = htobe16(1);

        key = dns_resource_key_new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_packet_append_key(packet, key, 0, NULL));
        dns_resource_key_unref(key);

        const uint8_t data[] = {
                        0x00, 0x2a,     BIT_RD, DNS_RCODE_SUCCESS,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* A */         0x00, 0x01,
        /* IN */        0x00, 0x01
        };

        ASSERT_EQ(packet->size, sizeof(data));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet), data, sizeof(data)), 0);
}

TEST(packet_append_key_single_soa_any_class) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsResourceKey *key = NULL;

        ASSERT_OK(dns_packet_new(&packet, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX));
        ASSERT_NOT_NULL(packet);

        DNS_PACKET_ID(packet) = htobe16(42);
        DNS_PACKET_HEADER(packet)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(0, 0, 0, 0, 1, 0, 0, 0, DNS_RCODE_SUCCESS));
        DNS_PACKET_HEADER(packet)->qdcount = htobe16(1);

        key = dns_resource_key_new(DNS_CLASS_ANY, DNS_TYPE_SOA, "www.example.com");
        ASSERT_NOT_NULL(key);
        ASSERT_OK(dns_packet_append_key(packet, key, 0, NULL));
        dns_resource_key_unref(key);

        const uint8_t data[] = {
                        0x00, 0x2a,     BIT_RD, DNS_RCODE_SUCCESS,
                        0x00, 0x01,     0x00, 0x00,     0x00, 0x00,     0x00, 0x00,

        /* name */      0x03, 'w', 'w', 'w',
                        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                        0x03, 'c', 'o', 'm',
                        0x00,
        /* SOA */       0x00, 0x06,
        /* ANY */       0x00, 0xff
        };

        ASSERT_EQ(packet->size, sizeof(data));
        ASSERT_EQ(memcmp(DNS_PACKET_DATA(packet), data, sizeof(data)), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
