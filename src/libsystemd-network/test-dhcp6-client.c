/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-dhcp6-protocol.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-option.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"
#include "unaligned.h"

#define DHCP6_CLIENT_EVENT_TEST_ADVERTISED 77
#define IA_ID_BYTES                                                     \
        0x0e, 0xcf, 0xa3, 0x7d
#define IA_NA_ADDRESS1_BYTES                                            \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x78, 0xee, 0x1c, 0xf3, 0x09, 0x3c, 0x55, 0xad
#define IA_NA_ADDRESS2_BYTES                                            \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x78, 0xee, 0x1c, 0xf3, 0x09, 0x3c, 0x55, 0xae
#define IA_PD_PREFIX1_BYTES                                             \
        0x2a, 0x02, 0x81, 0x0d, 0x98, 0x80, 0x37, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define IA_PD_PREFIX2_BYTES                                             \
        0x2a, 0x02, 0x81, 0x0d, 0x98, 0x80, 0x37, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define DNS1_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
#define DNS2_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
#define SNTP1_BYTES                                                     \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
#define SNTP2_BYTES                                                     \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
#define NTP1_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
#define NTP2_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
#define SIP1_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07
#define SIP2_BYTES                                                      \
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08
#define CLIENT_ID_BYTES                                                 \
        0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2
#define SERVER_ID_BYTES                                                 \
        0x00, 0x01, 0x00, 0x01, 0x19, 0x40, 0x5c, 0x53, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53
#define VENDOR_SUBOPTION_BYTES                                         \
        0x01

static const struct in6_addr local_address =
        { { { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, } } };
static const struct in6_addr mcast_address = IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS;
static const struct in6_addr ia_na_address1 = { { { IA_NA_ADDRESS1_BYTES } } };
static const struct in6_addr ia_na_address2 = { { { IA_NA_ADDRESS2_BYTES } } };
static const struct in6_addr ia_pd_prefix1 = { { { IA_PD_PREFIX1_BYTES } } };
static const struct in6_addr ia_pd_prefix2 = { { { IA_PD_PREFIX2_BYTES } } };
static const struct in6_addr dns1 = { { { DNS1_BYTES } } };
static const struct in6_addr dns2 = { { { DNS2_BYTES } } };
static const struct in6_addr sntp1 = { { { SNTP1_BYTES } } };
static const struct in6_addr sntp2 = { { { SNTP2_BYTES } } };
static const struct in6_addr ntp1 = { { { NTP1_BYTES } } };
static const struct in6_addr ntp2 = { { { NTP2_BYTES } } };
static const struct in6_addr sip1 = { { { SIP1_BYTES } } };
static const struct in6_addr sip2 = { { { SIP2_BYTES } } };
static const uint8_t client_id[] = { CLIENT_ID_BYTES };
static const uint8_t server_id[] = { SERVER_ID_BYTES };
static uint8_t vendor_suboption_data[] = { VENDOR_SUBOPTION_BYTES };
static const struct ether_addr mac = {
        .ether_addr_octet = { 'A', 'B', 'C', '1', '2', '3' },
};
static int test_fd[2] = EBADF_PAIR;
static sd_dhcp6_option vendor_suboption = {
        .n_ref = 1,
        .enterprise_identifier = 32,
        .option = 247,
        .data = vendor_suboption_data,
        .length = 1,
};
static int test_ifindex = 42;
static unsigned test_client_sent_message_count = 0;
static sd_dhcp6_client *client_ref = NULL;

typedef struct ClientOROTest {
        unsigned expect_n_address_registration;
        size_t n_automatic_options;
} ClientOROTest;

static ClientOROTest *client_oro_test = NULL;

TEST(client_basic) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        int v;

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(client);

        assert_se(sd_dhcp6_client_set_ifindex(client, 15) == 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, 42) >= 0);

        assert_se(sd_dhcp6_client_set_mac(client, mac.ether_addr_octet, sizeof(mac), ARPHRD_ETHER) >= 0);

        assert_se(sd_dhcp6_client_set_fqdn(client, "host") == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, "host.domain") == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, NULL) == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, "~host") == -EINVAL);
        assert_se(sd_dhcp6_client_set_fqdn(client, "~host.domain") == -EINVAL);

        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_CLIENTID) == -EINVAL);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_ADDRESS) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_VENDOR_OPTS) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, 10) == -EINVAL);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NIS_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NISP_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NIS_SERVER) == -EEXIST);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NISP_SERVER) == -EEXIST);

        assert_se(sd_dhcp6_client_set_information_request(client, 1) >= 0);
        v = 0;
        assert_se(sd_dhcp6_client_get_information_request(client, &v) >= 0);
        assert_se(v);
        assert_se(sd_dhcp6_client_set_information_request(client, 0) >= 0);
        v = 42;
        assert_se(sd_dhcp6_client_get_information_request(client, &v) >= 0);
        assert_se(v == 0);

        v = 0;
        assert_se(sd_dhcp6_client_get_address_request(client, &v) >= 0);
        assert_se(v);
        v = 0;
        assert_se(sd_dhcp6_client_set_address_request(client, 1) >= 0);
        assert_se(sd_dhcp6_client_get_address_request(client, &v) >= 0);
        assert_se(v);
        v = 42;
        assert_se(sd_dhcp6_client_set_address_request(client, 1) >= 0);
        assert_se(sd_dhcp6_client_get_address_request(client, &v) >= 0);
        assert_se(v);

        assert_se(sd_dhcp6_client_set_address_request(client, 1) >= 0);
        assert_se(sd_dhcp6_client_set_prefix_delegation(client, 1) >= 0);
        v = 0;
        assert_se(sd_dhcp6_client_get_address_request(client, &v) >= 0);
        assert_se(v);
        v = 0;
        assert_se(sd_dhcp6_client_get_prefix_delegation(client, &v) >= 0);
        assert_se(v);

        assert_se(sd_dhcp6_client_set_callback(client, NULL, NULL) >= 0);

        assert_se(sd_dhcp6_client_detach_event(client) >= 0);
}

TEST(parse_domain) {
        _cleanup_free_ char *domain = NULL;
        _cleanup_strv_free_ char **list = NULL;
        uint8_t *data;

        data = (uint8_t []) { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
        assert_se(dhcp6_option_parse_domainname(data, 13, &domain) >= 0);
        assert_se(domain);
        assert_se(streq(domain, "example.com"));
        domain = mfree(domain);

        data = (uint8_t []) { 4, 't', 'e', 's', 't' };
        ASSERT_OK(dhcp6_option_parse_domainname(data, 5, &domain));
        ASSERT_STREQ(domain, "test");
        domain = mfree(domain);

        data = (uint8_t []) { 0 };
        assert_se(dhcp6_option_parse_domainname(data, 1, &domain) < 0);

        data = (uint8_t []) { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
                              6, 'f', 'o', 'o', 'b', 'a', 'r', 0 };
        assert_se(dhcp6_option_parse_domainname_list(data, 21, &list) >= 0);
        assert_se(list);
        assert_se(streq(list[0], "example.com"));
        assert_se(streq(list[1], "foobar"));
        assert_se(!list[2]);
        list = strv_free(list);

        data = (uint8_t []) { 1, 'a', 0, 20, 'b', 'c' };
        assert_se(dhcp6_option_parse_domainname_list(data, 6, &list) < 0);

        data = (uint8_t []) { 0 , 0 };
        assert_se(dhcp6_option_parse_domainname_list(data, 2, &list) < 0);
}

TEST(option) {
        static const uint8_t packet[] = {
                'F', 'O', 'O', 'H', 'O', 'G', 'E',
                0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x07,
                'A', 'B', 'C', 'D', 'E', 'F', 'G',
                0x00, SD_DHCP6_OPTION_VENDOR_CLASS, 0x00, 0x09,
                '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'B', 'A', 'R',
        };
        static const uint8_t result[] = {
                'F', 'O', 'O', 'H', 'O', 'G', 'E',
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                'B', 'A', 'R',
        };
        _cleanup_free_ uint8_t *buf = NULL;
        size_t offset, pos, optlen;
        const uint8_t *optval;
        uint16_t optcode;

        assert_se(sizeof(packet) == sizeof(result));

        offset = 0;
        assert_se(dhcp6_option_parse(packet, 0, &offset, &optcode, &optlen, &optval) == -EBADMSG);

        offset = 3;
        assert_se(dhcp6_option_parse(packet, 0, &offset, &optcode, &optlen, &optval) == -EBADMSG);

        /* Tests for reading unaligned data. */
        assert_se(buf = new(uint8_t, sizeof(packet)));
        for (size_t i = 0; i <= 7; i++) {
                memcpy(buf, packet + i, sizeof(packet) - i);
                offset = 7 - i;
                assert_se(dhcp6_option_parse(buf, sizeof(packet), &offset, &optcode, &optlen, &optval) >= 0);

                assert_se(optcode == SD_DHCP6_OPTION_ORO);
                assert_se(optlen == 7);
                assert_se(optval == buf + 11 - i);
        }

        offset = 7;
        assert_se(dhcp6_option_parse(packet, sizeof(packet), &offset, &optcode, &optlen, &optval) >= 0);

        assert_se(optcode == SD_DHCP6_OPTION_ORO);
        assert_se(optlen == 7);
        assert_se(optval == packet + 11);

        free(buf);
        assert_se(buf = memdup(result, sizeof(result)));
        pos = 7;
        assert_se(dhcp6_option_append(&buf, &pos, optcode, optlen, optval) >= 0);

        assert_se(dhcp6_option_parse(packet, sizeof(packet), &offset, &optcode, &optlen, &optval) >= 0);

        assert_se(optcode == SD_DHCP6_OPTION_VENDOR_CLASS);
        assert_se(optlen == 9);
        assert_se(optval == packet + 22);

        assert_se(dhcp6_option_append(&buf, &pos, optcode, optlen, optval) >= 0);

        assert_se(memcmp(packet, buf, sizeof(packet)) == 0);
}

TEST(option_status) {
        uint8_t option1[] = {
                /* IA NA */
                0x00, 0x03, 0x00, 0x12, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x01,
        };
        static const uint8_t option2[] = {
                /* IA NA */
                0x00, 0x03, 0x00, 0x2e, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* IA Addr */
                0x00, 0x05, 0x00, 0x1e,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
                /* IA address status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x01,
        };
        static const uint8_t option3[] = {
                /* IA NA */
                0x00, 0x03, 0x00, 0x34, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* IA Addr */
                0x00, 0x05, 0x00, 0x24,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
                /* IA address status option */
                0x00, 0x0d, 0x00, 0x08, 0x00, 0x00, 'f',  'o',
                'o',  'b',  'a',  'r',
        };
        static const uint8_t option4[] = {
                /* IA PD */
                0x00, 0x19, 0x00, 0x2f, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* IA PD Prefix */
                0x00, 0x1a, 0x00, 0x1f,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x80, 0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe,
                0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
                /* PD prefix status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x00,
        };
        static const uint8_t option5[] = {
                /* IA PD */
                0x00, 0x19, 0x00, 0x52, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* IA PD Prefix #1 */
                0x00, 0x1a, 0x00, 0x1f,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x80, 0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe,
                0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
                /* PD prefix status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x00,
                /* IA PD Prefix #2 */
                0x00, 0x1a, 0x00, 0x1f,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x80, 0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x0l, 0xd0,
                0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
                /* PD prefix status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x00,
        };
        static const uint8_t option6[] = {
                /* IA PD */
                0x00, 0x19, 0x00, 0x29, 0x1a, 0x1d, 0x1a, 0x1d,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02,
                /* IA PD Prefix, with an invalid prefix length of 0 */
                0x00, 0x1a, 0x00, 0x19,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
        };
        _cleanup_(dhcp6_ia_freep) DHCP6IA *ia = NULL;
        DHCP6Option *option;
        be32_t iaid;
        int r;

        memcpy(&iaid, option1 + 4, sizeof(iaid));

        option = (DHCP6Option*) option1;
        assert_se(sizeof(option1) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(NULL, 0, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -ENOANO);

        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -EINVAL);

        option->len = htobe16(17);
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -EBADMSG);

        option->len = htobe16(sizeof(DHCP6Option));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -EBADMSG);

        option = (DHCP6Option*) option2;
        assert_se(sizeof(option2) == sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -ENODATA);

        option = (DHCP6Option*) option3;
        assert_se(sizeof(option3) == sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r >= 0);
        assert_se(ia);
        assert_se(ia->addresses);
        ia = dhcp6_ia_free(ia);

        option = (DHCP6Option*) option4;
        assert_se(sizeof(option4) == sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r >= 0);
        assert_se(ia);
        assert_se(ia->addresses);
        assert_se(memcmp(&ia->header.id, &option4[4], 4) == 0);
        assert_se(memcmp(&ia->header.lifetime_t1, &option4[8], 4) == 0);
        assert_se(memcmp(&ia->header.lifetime_t2, &option4[12], 4) == 0);
        ia = dhcp6_ia_free(ia);

        option = (DHCP6Option*) option5;
        assert_se(sizeof(option5) == sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r >= 0);
        assert_se(ia);
        assert_se(ia->addresses);
        ia = dhcp6_ia_free(ia);

        /* An IA_PD whose only prefix carries an invalid (zero) prefix length must be refused, leaving no
         * valid prefix behind. */
        option = (DHCP6Option*) option6;
        assert_se(sizeof(option6) == sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        assert_se(r == -ENODATA);
        assert_se(!ia);
}

static void test_client_verify_oro(
                const uint8_t *packet,
                size_t len,
                unsigned expect_n_address_registration,
                size_t n_automatic_options) {

        size_t offset = offsetof(DHCP6Message, options), optlen;
        const uint8_t *optval;
        unsigned n_address_registration = 0, n_oro = 0;
        uint16_t optcode;

        while (offset < len) {
                ASSERT_OK(dhcp6_option_parse(packet, len, &offset, &optcode, &optlen, &optval));
                if (optcode != SD_DHCP6_OPTION_ORO)
                        continue;

                n_oro++;
                ASSERT_EQ(optlen,
                          (1 + n_automatic_options + expect_n_address_registration) * sizeof(be16_t));

                for (size_t i = 0; i < optlen / sizeof(be16_t); i++)
                        if (unaligned_read_be16(optval + i * sizeof(be16_t)) ==
                            SD_DHCP6_OPTION_ADDR_REG_ENABLE)
                                n_address_registration++;
        }

        ASSERT_EQ(n_oro, 1U);
        ASSERT_EQ(n_address_registration, expect_n_address_registration);
}

static void test_client_oro_one(DHCP6State state, bool enabled, bool requested, size_t n_automatic_options) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, event, 0));
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(
                          client,
                          unaligned_read_be16(client_id),
                          client_id + sizeof(be16_t),
                          sizeof(client_id) - sizeof(be16_t)));
        ASSERT_OK(dhcp6_client_set_address_registration_enabled(client, enabled));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER));
        if (requested)
                ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_ADDR_REG_ENABLE));

        if (IN_SET(state, DHCP6_STATE_REQUEST, DHCP6_STATE_RENEW, DHCP6_STATE_REBIND)) {
                ASSERT_OK(dhcp6_lease_new(&client->lease));
                ASSERT_OK(dhcp6_lease_set_serverid(client->lease, server_id, sizeof(server_id)));
        }

        client->state = state;

        ASSERT_NULL(client_oro_test);
        client_oro_test = &(ClientOROTest) {
                        .expect_n_address_registration = enabled + requested,
                        .n_automatic_options = n_automatic_options,
        };
        ASSERT_OK(dhcp6_client_send_message(client));
        client_oro_test = NULL;
}

TEST(client_oro_address_registration) {
        DHCP6State state;

        FOREACH_ARGUMENT(state,
                         DHCP6_STATE_INFORMATION_REQUEST,
                         DHCP6_STATE_SOLICITATION,
                         DHCP6_STATE_REQUEST,
                         DHCP6_STATE_RENEW,
                         DHCP6_STATE_REBIND)
                for (unsigned enabled = 0; enabled <= 1; enabled++)
                        for (unsigned requested = 0; requested <= 1; requested++)
                                test_client_oro_one(
                                                state,
                                                enabled,
                                                requested,
                                                state == DHCP6_STATE_INFORMATION_REQUEST ? 2 :
                                                state == DHCP6_STATE_SOLICITATION ? 1 : 0);
}

TEST(client_parse_message_issue_22099) {
        static const uint8_t msg[] = {
                /* Message type */
                DHCP6_MESSAGE_REPLY,
                /* Transaction ID */
                0x7c, 0x4c, 0x16,
                /* Rapid commit */
                0x00, SD_DHCP6_OPTION_RAPID_COMMIT, 0x00, 0x00,
                /* NTP servers */
                0x00, SD_DHCP6_OPTION_NTP_SERVER, 0x00, 0x14,
                /* NTP server (broken sub option and sub option length) */
                0x01, 0x00, 0x10, 0x00,
                0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0x15, 0xc8, 0xff, 0xfe, 0xef, 0x1e, 0x4e,
                /* Client ID */
                0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
                0x00, 0x02, /* DUID-EN */
                0x00, 0x00, 0xab, 0x11, /* pen */
                0x5c, 0x6b, 0x90, 0xec, 0xda, 0x95, 0x15, 0x45, /* id */
                /* Server ID */
                0x00, SD_DHCP6_OPTION_SERVERID, 0x00, 0x0a,
                0x00, 0x03, /* DUID-LL */
                0x00, 0x01, /* htype */
                0xdc, 0x15, 0xc8, 0xef, 0x1e, 0x4e, /* haddr */
                /* preference */
                0x00, SD_DHCP6_OPTION_PREFERENCE, 0x00, 0x01,
                0x00,
                /* DNS servers */
                0x00, SD_DHCP6_OPTION_DNS_SERVER, 0x00, 0x10,
                0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0x15, 0xc8, 0xff, 0xfe, 0xef, 0x1e, 0x4e,
                /* v6 pcp server */
                0x00, SD_DHCP6_OPTION_V6_PCP_SERVER, 0x00, 0x10,
                0x2a, 0x02, 0x81, 0x0d, 0x98, 0x80, 0x37, 0x00, 0xde, 0x15, 0xc8, 0xff, 0xfe, 0xef, 0x1e, 0x4e,
                /* IA_NA */
                0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x28,
                0xcc, 0x59, 0x11, 0x7b, /* iaid */
                0x00, 0x00, 0x07, 0x08, /* lifetime T1 */
                0x00, 0x00, 0x0b, 0x40, /* lifetime T2 */
                /* IA_NA (iaaddr suboption) */
                0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
                0x2a, 0x02, 0x81, 0x0d, 0x98, 0x80, 0x37, 0x00, 0x6a, 0x05, 0xca, 0xff, 0xfe, 0xf1, 0x51, 0x53, /* address */
                0x00, 0x00, 0x0e, 0x10, /* preferred lifetime */
                0x00, 0x00, 0x1c, 0x20, /* valid lifetime */
                /* IA_PD */
                0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x29,
                0xcc, 0x59, 0x11, 0x7b, /* iaid */
                0x00, 0x00, 0x07, 0x08, /* lifetime T1 */
                0x00, 0x00, 0x0b, 0x40, /* lifetime T2 */
                /* IA_PD (iaprefix suboption) */
                0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
                0x00, 0x00, 0x0e, 0x10, /* preferred lifetime */
                0x00, 0x00, 0x1c, 0x20, /* valid lifetime */
                0x3a, /* prefixlen */
                0x2a, 0x02, 0x81, 0x0d, 0x98, 0x80, 0x37, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* prefix */
        };
        static const uint8_t duid[] = {
                0x00, 0x00, 0xab, 0x11, 0x5c, 0x6b, 0x90, 0xec, 0xda, 0x95, 0x15, 0x45,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_set_iaid(client, 0xcc59117b) >= 0);
        assert_se(sd_dhcp6_client_set_duid_raw(client, 2, duid, sizeof(duid)) >= 0);

        assert_se(dhcp6_lease_new_from_message(client, (const DHCP6Message*) msg, sizeof(msg), NULL, NULL, &lease) >= 0);
}

TEST(client_parse_message_issue_24002) {
        static const uint8_t msg[] = {
                /* Message Type */
                0x07,
                /* Transaction ID */
                0x0e, 0xa5, 0x7c,
                /* Client ID */
                0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
                0x00, 0x02, /* DUID-EN */
                0x00, 0x00, 0xab, 0x11, /* pen */
                0x5c, 0x6b, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* id */
                /* Server ID */
                0x00, 0x02, 0x00, 0x1a,
                0x00, 0x02, 0x00, 0x00, 0x05, 0x83, 0x30, 0x63, 0x3a, 0x38, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                /* IA_PD */
                0x00, 0x19, 0x00, 0x29,
                0xaa, 0xbb, 0xcc, 0xdd, /* iaid */
                0x00, 0x00, 0x03, 0x84, /* lifetime (T1) */
                0x00, 0x00, 0x05, 0xa0, /* lifetime (T2) */
                /* IA_PD (iaprefix suboption) */
                0x00, 0x1a, 0x00, 0x19,
                0x00, 0x00, 0x07, 0x08, /* preferred lifetime */
                0x00, 0x00, 0x38, 0x40, /* valid lifetime */
                0x38, /* prefixlen */
                0x20, 0x03, 0x00, 0xff, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* prefix */
                /* Rapid commit */
                0x00, 0x0e, 0x00, 0x00,
                /* Trailing invalid byte at the end. See issue #28183. */
                00,
        };
        static const uint8_t duid[] = {
                0x00, 0x00, 0xab, 0x11, 0x5c, 0x6b, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_set_iaid(client, 0xaabbccdd) >= 0);
        assert_se(sd_dhcp6_client_set_duid_raw(client, 2, duid, sizeof(duid)) >= 0);

        assert_se(dhcp6_lease_new_from_message(client, (const DHCP6Message*) msg, sizeof(msg), NULL, NULL, &lease) >= 0);
}

static const uint8_t msg_information_request[] = {
        /* Message type */
        DHCP6_MESSAGE_INFORMATION_REQUEST,
        /* Transaction ID */
        0x0f, 0xb4, 0xe5,
        /* MUD URL */
        /* ORO */
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x0e,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
        0x00, SD_DHCP6_OPTION_INF_MAX_RT,
        0x00, SD_DHCP6_OPTION_ADDR_REG_ENABLE,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Extra options */
        /* Elapsed time */
        0x00, SD_DHCP6_OPTION_ELAPSED_TIME, 0x00, 0x02,
        0x00, 0x00,
};

static const uint8_t msg_solicit[] = {
        /* Message type */
        DHCP6_MESSAGE_SOLICIT,
        /* Transaction ID */
        0x0f, 0xb4, 0xe5,
        /* Rapid commit */
        0x00, SD_DHCP6_OPTION_RAPID_COMMIT, 0x00, 0x00,
        /* IA_NA */
        0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x0c,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* IA_PD */
        0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x0c,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x11,
        DHCP6_FQDN_FLAG_S,
        0x04, 'h', 'o', 's', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* User Class */
        /* Vendor Class */
        /* Vendor Options */
        /* MUD URL */
        /* ORO */
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x0c,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
        0x00, SD_DHCP6_OPTION_SOL_MAX_RT,
        0x00, SD_DHCP6_OPTION_ADDR_REG_ENABLE,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Extra options */
        /* Elapsed time */
        0x00, SD_DHCP6_OPTION_ELAPSED_TIME, 0x00, 0x02,
        0x00, 0x00,
};

static const uint8_t msg_request[] = {
        /* Message type */
        DHCP6_MESSAGE_REQUEST,
        /* Transaction ID */
        0x00, 0x00, 0x00,
        /* Server ID */
        0x00, SD_DHCP6_OPTION_SERVERID, 0x00, 0x0e,
        SERVER_ID_BYTES,
        /* IA_NA */
        0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x44,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS1_BYTES,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS2_BYTES,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        /* IA_PD */
        0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x46,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX1_BYTES,
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX2_BYTES,
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x11,
        DHCP6_FQDN_FLAG_S,
        0x04, 'h', 'o', 's', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* User Class */
        /* Vendor Class */
        /* Vendor Options */
        /* MUD URL */
        /* ORO */
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x0a,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
        0x00, SD_DHCP6_OPTION_ADDR_REG_ENABLE,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Extra options */
        /* Elapsed time */
        0x00, SD_DHCP6_OPTION_ELAPSED_TIME, 0x00, 0x02,
        0x00, 0x00,
};

/* RFC 3315 section 18.1.6. The DHCP6 Release message must include:
    - transaction id
    - server identifier
    - client identifier
    - all released IA with addresses included
    - elapsed time (required for all messages).
    All other options aren't required. */
static const uint8_t msg_release[] = {
        /* Message type */
        DHCP6_MESSAGE_RELEASE,
        /* Transaction ID */
        0x00, 0x00, 0x00,
        /* Server ID */
        0x00, SD_DHCP6_OPTION_SERVERID, 0x00, 0x0e,
        SERVER_ID_BYTES,
        /* IA_NA */
        0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x44,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS1_BYTES,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS2_BYTES,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        /* IA_PD */
        0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x46,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x00, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x00, /* lifetime T2 */
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX1_BYTES,
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x00, /* preferred lifetime */
        0x00, 0x00, 0x00, 0x00, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX2_BYTES,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Extra options */
        /* Elapsed time */
        0x00, SD_DHCP6_OPTION_ELAPSED_TIME, 0x00, 0x02,
        0x00, 0x00,
};

static const uint8_t msg_reply[] = {
        /* Message type */
        DHCP6_MESSAGE_REPLY,
        /* Transaction ID */
        0x0f, 0xb4, 0xe5,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Server ID */
        0x00, SD_DHCP6_OPTION_SERVERID, 0x00, 0x0e,
        SERVER_ID_BYTES,
        /* Rapid commit */
        0x00, SD_DHCP6_OPTION_RAPID_COMMIT, 0x00, 0x01,
        0x00,
        /* IA_NA */
        0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x66,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x50, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x78, /* lifetime T2 */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS2_BYTES,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS1_BYTES,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        /* IA_NA (status code suboption) */
        0x00, SD_DHCP6_OPTION_STATUS_CODE, 0x00, 0x1e,
        0x00, 0x00, /* status code */
        0x41, 0x6c, 0x6c, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x20, 0x77, 0x65,
        0x72, 0x65, 0x20, 0x61, 0x73, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x2e, /* status message */
        /* IA_PD */
        0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x46,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x50, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x78, /* lifetime T2 */
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX2_BYTES,
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX1_BYTES,
        /* DNS servers */
        0x00, SD_DHCP6_OPTION_DNS_SERVER, 0x00, 0x20,
        DNS1_BYTES,
        DNS2_BYTES,
        /* SNTP servers */
        0x00, SD_DHCP6_OPTION_SNTP_SERVER, 0x00, 0x20,
        SNTP1_BYTES,
        SNTP2_BYTES,
        /* NTP servers */
        0x00, SD_DHCP6_OPTION_NTP_SERVER, 0x00, 0x37,
        /* NTP server (address suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_ADDR, 0x00, 0x10,
        NTP1_BYTES,
        /* NTP server (address suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_ADDR, 0x00, 0x10,
        NTP2_BYTES,
        /* NTP server (fqdn suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_FQDN, 0x00, 0x0b,
        0x03, 'n', 't', 'p', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* SIP server addresses */
        0x00, SD_DHCP6_OPTION_SIP_SERVER_ADDRESS, 0x00, 0x20,
        SIP1_BYTES,
        SIP2_BYTES,
        /* SIP server domains */
        0x00, SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME, 0x00, 0x0b,
        0x03, 's', 'i', 'p', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Domain list */
        0x00, SD_DHCP6_OPTION_DOMAIN, 0x00, 0x0b,
        0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x13,
        0x01, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Vendor specific options */
        0x00, SD_DHCP6_OPTION_VENDOR_OPTS, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x20, 0x00, 0xf7, 0x00, 0x01, VENDOR_SUBOPTION_BYTES,
};

static const uint8_t msg_advertise[] = {
        /* Message type */
        DHCP6_MESSAGE_ADVERTISE,
        /* Transaction ID */
        0x0f, 0xb4, 0xe5,
        /* Client ID */
        0x00, SD_DHCP6_OPTION_CLIENTID, 0x00, 0x0e,
        CLIENT_ID_BYTES,
        /* Server ID */
        0x00, SD_DHCP6_OPTION_SERVERID, 0x00, 0x0e,
        SERVER_ID_BYTES,
        /* Preference */
        0x00, SD_DHCP6_OPTION_PREFERENCE, 0x00, 0x01,
        0xff,
        /* IA_NA */
        0x00, SD_DHCP6_OPTION_IA_NA, 0x00, 0x7a,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x50, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x78, /* lifetime T2 */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS2_BYTES, /* address */
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        /* IA_NA (IAADDR suboption) */
        0x00, SD_DHCP6_OPTION_IAADDR, 0x00, 0x18,
        IA_NA_ADDRESS1_BYTES, /* address */
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        /* IA_NA (status code suboption) */
        0x00, SD_DHCP6_OPTION_STATUS_CODE, 0x00, 0x32,
        0x00, 0x00, /* status code */
        0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x28, 0x65, 0x73, 0x29, 0x20, 0x72, 0x65, 0x6e, 0x65,
        0x77, 0x65, 0x64, 0x2e, 0x20, 0x47, 0x72, 0x65, 0x65, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x20, 0x66,
        0x72, 0x6f, 0x6d, 0x20, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x74, 0x20, 0x45, 0x61, 0x72, 0x74, 0x68, /* status message */
        /* IA_PD */
        0x00, SD_DHCP6_OPTION_IA_PD, 0x00, 0x46,
        IA_ID_BYTES,
        0x00, 0x00, 0x00, 0x50, /* lifetime T1 */
        0x00, 0x00, 0x00, 0x78, /* lifetime T2 */
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX2_BYTES,
        /* IA_PD (IA_PD_PREFIX suboption) */
        0x00, SD_DHCP6_OPTION_IA_PD_PREFIX, 0x00, 0x19,
        0x00, 0x00, 0x00, 0x96, /* preferred lifetime */
        0x00, 0x00, 0x00, 0xb4, /* valid lifetime */
        0x40, /* prefixlen */
        IA_PD_PREFIX1_BYTES,
        /* DNS servers */
        0x00, SD_DHCP6_OPTION_DNS_SERVER, 0x00, 0x20,
        DNS1_BYTES,
        DNS2_BYTES,
        /* SNTP servers */
        0x00, SD_DHCP6_OPTION_SNTP_SERVER, 0x00, 0x20,
        SNTP1_BYTES,
        SNTP2_BYTES,
        /* NTP servers */
        0x00, SD_DHCP6_OPTION_NTP_SERVER, 0x00, 0x37,
        /* NTP server (address suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_ADDR, 0x00, 0x10,
        NTP1_BYTES,
        /* NTP server (address suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_ADDR, 0x00, 0x10,
        NTP2_BYTES,
        /* NTP server (fqdn suboption) */
        0x00, DHCP6_NTP_SUBOPTION_SRV_FQDN, 0x00, 0x0b,
        0x03, 'n', 't', 'p', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* SIP server addresses */
        0x00, SD_DHCP6_OPTION_SIP_SERVER_ADDRESS, 0x00, 0x20,
        SIP1_BYTES,
        SIP2_BYTES,
        /* SIP server domains */
        0x00, SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME, 0x00, 0x0b,
        0x03, 's', 'i', 'p', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Domain list */
        0x00, SD_DHCP6_OPTION_DOMAIN, 0x00, 0x0b,
        0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x13,
        0x01, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Vendor specific options */
        0x00, SD_DHCP6_OPTION_VENDOR_OPTS, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x20, 0x00, 0xf7, 0x00, 0x01, VENDOR_SUBOPTION_BYTES,
};

TEST(address_registration_capability) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        _cleanup_free_ uint8_t *buf = NULL;
        size_t offset;

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_TRUE(client->address_registration.enabled);
        ASSERT_FALSE(client->address_registration.supported);
        ASSERT_OK(sd_dhcp6_client_set_iaid(client, unaligned_read_be32((const uint8_t[]) { IA_ID_BYTES })));
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(
                        client,
                        unaligned_read_be16(client_id),
                        client_id + sizeof(be16_t),
                        sizeof(client_id) - sizeof(be16_t)));

        buf = memdup(msg_advertise, sizeof(msg_advertise));
        ASSERT_NOT_NULL(buf);
        offset = sizeof(msg_advertise);
        ASSERT_OK(dhcp6_option_append(&buf, &offset, SD_DHCP6_OPTION_ADDR_REG_ENABLE, 0, NULL));
        ASSERT_OK(dhcp6_lease_new_from_message(
                        client, (DHCP6Message*) buf, offset, NULL, NULL, &lease));
        ASSERT_TRUE(lease->address_registration_supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_SOLICIT, lease->address_registration_supported), 0);
        ASSERT_FALSE(client->address_registration.supported);
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, lease->address_registration_supported), 1);
        ASSERT_TRUE(client->address_registration.supported);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ false), 0);
        ASSERT_TRUE(client->address_registration.supported);

        /* Restarting DHCPv6 on the same attachment must not discard discovered support. */
        ASSERT_OK(sd_dhcp6_client_stop(client));
        ASSERT_TRUE(client->address_registration.supported);

        dhcp6_client_address_registration_reset(client);
        ASSERT_FALSE(client->address_registration.supported);

        lease = sd_dhcp6_lease_unref(lease);
        buf = mfree(buf);
        buf = memdup(msg_advertise, sizeof(msg_advertise));
        ASSERT_NOT_NULL(buf);
        offset = sizeof(msg_advertise);
        ASSERT_OK(dhcp6_option_append(
                        &buf, &offset, SD_DHCP6_OPTION_ADDR_REG_ENABLE, 1, &(const uint8_t) { 1 }));
        ASSERT_OK(dhcp6_lease_new_from_message(
                        client, (DHCP6Message*) buf, offset, NULL, NULL, &lease));
        ASSERT_FALSE(lease->address_registration_supported);
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, lease->address_registration_supported), 0);

        ASSERT_OK(dhcp6_client_set_address_registration_enabled(client, false));
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 0);
        ASSERT_FALSE(client->address_registration.supported);
}

typedef struct AddressRegistrationSentPacket {
        struct in6_addr source;
        struct sockaddr_in6 destination;
        int ifindex;
        uint8_t message_type;
        be32_t transaction_id;
        struct iaaddr iaaddr;
        unsigned n_client_id;
        unsigned n_iaaddr;
        unsigned n_oro;
        unsigned n_server_id;
} AddressRegistrationSentPacket;

typedef struct AddressRegistrationTest {
        unsigned n_open;
        unsigned n_open_failures;
        unsigned n_send_attempts;
        unsigned n_send_failures;
        unsigned n_sent;
        unsigned n_received;
        uint32_t next_transaction_id;
        uint64_t random_value;
        AddressRegistrationSentPacket sent[16];

        uint8_t receive_packet[256];
        size_t receive_len;
        struct sockaddr_in6 receive_sender;
        struct in6_addr receive_destination;
        int receive_ifindex;
        bool receive_truncated;
} AddressRegistrationTest;

static AddressRegistrationTest default_address_registration_test;
static AddressRegistrationTest *address_registration_test = &default_address_registration_test;

int dhcp6_address_registration_open_socket(int ifindex) {
        AddressRegistrationTest *test = ASSERT_PTR(address_registration_test);

        ASSERT_GT(ifindex, 0);
        test->n_open++;

        if (test->n_open_failures > 0) {
                test->n_open_failures--;
                return -EIO;
        }

        return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
}

int dhcp6_address_registration_send(
                int fd,
                const struct in6_addr *source,
                int ifindex,
                const struct sockaddr_in6 *destination,
                const void *packet,
                size_t len) {

        AddressRegistrationTest *test = ASSERT_PTR(address_registration_test);
        const DHCP6Message *message = ASSERT_PTR(packet);
        AddressRegistrationSentPacket *sent;
        size_t offset = offsetof(DHCP6Message, options);

        ASSERT_GE(fd, 0);
        test->n_send_attempts++;
        if (test->n_send_failures > 0) {
                test->n_send_failures--;
                return -EIO;
        }

        ASSERT_LT(test->n_sent, ELEMENTSOF(test->sent));
        ASSERT_GE(len, sizeof(DHCP6Message));

        sent = &test->sent[test->n_sent++];
        *sent = (AddressRegistrationSentPacket) {
                .source = *ASSERT_PTR(source),
                .destination = *ASSERT_PTR(destination),
                .ifindex = ifindex,
                .message_type = message->type,
                .transaction_id = message->transaction_id & htobe32(0x00ffffffU),
        };

        while (offset < len) {
                const uint8_t *optval;
                size_t optlen;
                uint16_t optcode;

                ASSERT_OK(dhcp6_option_parse(packet, len, &offset, &optcode, &optlen, &optval));

                switch (optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        sent->n_client_id++;
                        ASSERT_EQ(optlen, sizeof(client_id));
                        ASSERT_EQ(memcmp(optval, client_id, optlen), 0);
                        break;
                case SD_DHCP6_OPTION_IAADDR:
                        sent->n_iaaddr++;
                        ASSERT_EQ(optlen, sizeof(sent->iaaddr));
                        memcpy(&sent->iaaddr, optval, sizeof(sent->iaaddr));
                        break;
                case SD_DHCP6_OPTION_ORO:
                        sent->n_oro++;
                        break;
                case SD_DHCP6_OPTION_SERVERID:
                        sent->n_server_id++;
                        break;
                default:
                        assert_not_reached();
                }
        }

        return 0;
}

int dhcp6_address_registration_receive(
                int fd,
                void **ret_packet,
                size_t *ret_len,
                struct sockaddr_in6 *ret_sender,
                struct in6_addr *ret_destination,
                int *ret_ifindex,
                bool *ret_truncated) {

        AddressRegistrationTest *test = ASSERT_PTR(address_registration_test);
        void *packet;

        ASSERT_GE(fd, 0);

        packet = memdup(test->receive_packet, test->receive_len);
        if (!packet)
                return -ENOMEM;

        test->n_received++;
        *ret_packet = packet;
        *ret_len = test->receive_len;
        *ret_sender = test->receive_sender;
        *ret_destination = test->receive_destination;
        *ret_ifindex = test->receive_ifindex;
        *ret_truncated = test->receive_truncated;
        return 0;
}

uint32_t dhcp6_address_registration_random_u32(void) {
        AddressRegistrationTest *test = ASSERT_PTR(address_registration_test);

        return test->next_transaction_id++;
}

uint64_t dhcp6_address_registration_random_u64_range(uint64_t upper_bound) {
        AddressRegistrationTest *test = ASSERT_PTR(address_registration_test);

        ASSERT_GT(upper_bound, 0U);
        return test->random_value % upper_bound;
}

static DHCP6AddressRegistration *test_address_registration_get(
                sd_dhcp6_client *client,
                const struct in6_addr *address) {

        return hashmap_get(client->address_registration.registrations, address);
}

static sd_dhcp6_client *test_address_registration_client_new(AddressRegistrationTest *test) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;

        address_registration_test = ASSERT_PTR(test);

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_set_ifindex(client, test_ifindex));
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(
                        client,
                        unaligned_read_be16(client_id),
                        client_id + sizeof(be16_t),
                        sizeof(client_id) - sizeof(be16_t)));
        return TAKE_PTR(client);
}

static uint8_t *test_address_registration_reply(
                be32_t transaction_id,
                const struct in6_addr *address,
                unsigned n_addresses,
                size_t iaaddr_size,
                size_t *ret_len) {

        _cleanup_free_ uint8_t *buf = NULL;
        DHCP6Message *message;
        size_t offset;

        ASSERT_NOT_NULL(buf = new0(uint8_t, sizeof(DHCP6Message)));

        message = (DHCP6Message*) buf;
        message->transaction_id = transaction_id;
        message->type = DHCP6_MESSAGE_ADDR_REG_REPLY;
        offset = sizeof(DHCP6Message);

        for (unsigned i = 0; i < n_addresses; i++) {
                const struct iaaddr iaaddr = {
                        .address = *ASSERT_PTR(address),
                        .lifetime_preferred = htobe32(10),
                        .lifetime_valid = htobe32(20),
                };

                ASSERT_LE(iaaddr_size, sizeof(iaaddr));
                ASSERT_OK(dhcp6_option_append(
                                &buf, &offset, SD_DHCP6_OPTION_IAADDR, iaaddr_size, &iaaddr));
        }

        *ret_len = offset;
        return TAKE_PTR(buf);
}

TEST(address_registration_exchange) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x123456,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);
        const usec_t now_usec = 100 * USEC_PER_SEC;
        DHCP6AddressRegistration *registration;

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
        ASSERT_EQ(test.n_open, 0U);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client,
                          &ia_na_address1,
                          now_usec + 10 * USEC_PER_SEC,
                          now_usec + 20 * USEC_PER_SEC,
                          now_usec), 1);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 1U);
        ASSERT_EQ(test.n_open, 1U);
        ASSERT_EQ(test.n_sent, 1U);

        AddressRegistrationSentPacket *sent = &test.sent[0];
        ASSERT_EQ(sent->message_type, DHCP6_MESSAGE_ADDR_REG_INFORM);
        ASSERT_EQ(be32toh(sent->transaction_id), 0x123456U);
        ASSERT_EQ(sent->ifindex, test_ifindex);
        ASSERT_TRUE(in6_addr_equal(&sent->source, &ia_na_address1));
        ASSERT_EQ(sent->destination.sin6_family, AF_INET6);
        ASSERT_TRUE(in6_addr_equal(
                        &sent->destination.sin6_addr,
                        &IN6_ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS));
        ASSERT_EQ(sent->destination.sin6_port, htobe16(DHCP6_PORT_SERVER));
        ASSERT_EQ(sent->destination.sin6_scope_id, (uint32_t) test_ifindex);
        ASSERT_EQ(sent->n_client_id, 1U);
        ASSERT_EQ(sent->n_iaaddr, 1U);
        ASSERT_EQ(sent->n_oro, 0U);
        ASSERT_EQ(sent->n_server_id, 0U);
        struct in6_addr sent_address;
        memcpy(&sent_address, &sent->iaaddr.address, sizeof(sent_address));
        ASSERT_TRUE(in6_addr_equal(&sent_address, &ia_na_address1));
        ASSERT_EQ(be32toh(sent->iaaddr.lifetime_preferred), 10U);
        ASSERT_EQ(be32toh(sent->iaaddr.lifetime_valid), 20U);

        registration = ASSERT_PTR(test_address_registration_get(client, &ia_na_address1));
        ASSERT_TRUE(registration->transaction_active);
        ASSERT_EQ(registration->transmission_count, 1U);
        ASSERT_EQ(registration->retransmit_deadline_usec, now_usec + 900 * USEC_PER_MSEC);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client,
                          &ia_na_address1,
                          now_usec + 30 * USEC_PER_SEC,
                          now_usec + 40 * USEC_PER_SEC,
                          now_usec), 1);
        ASSERT_EQ(test.n_sent, 1U);

        ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                          client, &ia_na_address1, now_usec + USEC_PER_SEC), 1);
        ASSERT_EQ(test.n_sent, 2U);
        ASSERT_EQ(test.sent[1].transaction_id, test.sent[0].transaction_id);
        ASSERT_EQ(be32toh(test.sent[1].iaaddr.lifetime_preferred), 29U);
        ASSERT_EQ(be32toh(test.sent[1].iaaddr.lifetime_valid), 39U);

        ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                          client, &ia_na_address1, now_usec + 2 * USEC_PER_SEC), 1);
        ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                          client, &ia_na_address1, now_usec + 3 * USEC_PER_SEC), 0);
        ASSERT_EQ(test.n_sent, 3U);
        ASSERT_FALSE(registration->transaction_active);

        for (unsigned i = 1; i < test.n_sent; i++)
                ASSERT_EQ(test.sent[i].transaction_id, test.sent[0].transaction_id);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address2, USEC_INFINITY, USEC_INFINITY, now_usec), 1);
        ASSERT_EQ(test.n_open, 1U);
        ASSERT_EQ(test.n_sent, 4U);
        ASSERT_EQ(be32toh(test.sent[3].iaaddr.lifetime_preferred), UINT32_MAX);
        ASSERT_EQ(be32toh(test.sent[3].iaaddr.lifetime_valid), UINT32_MAX);

        dhcp6_client_remove_address_registration(client, &ia_na_address1);
        dhcp6_client_remove_address_registration(client, &ia_na_address2);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 0U);
}

TEST(address_registration_mrc) {
        static const struct {
                unsigned mrc;
                unsigned expected_transmissions;
                bool expected_active;
        } cases[] = {
                { 1, 1, false },
                { 3, 3, false },
                { 0, 6, true  },
        };

        FOREACH_ELEMENT(c, cases) {
                AddressRegistrationTest test = {
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                client->address_registration.max_retransmissions = c->mrc;
                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_EQ(dhcp6_client_update_address_registration_at(
                                  client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, 0), 1);

                for (unsigned i = 1; i <= 5; i++)
                        (void) dhcp6_client_address_registration_retransmit_at(
                                        client, &ia_na_address1, i * USEC_PER_SEC);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                ASSERT_EQ(test.n_sent, c->expected_transmissions);
                ASSERT_EQ(registration->transmission_count, c->expected_transmissions);
                ASSERT_EQ(registration->transaction_active, c->expected_active);
        }
}

TEST(address_registration_network_failures) {
        const usec_t now_usec = 100 * USEC_PER_SEC;

        {
                AddressRegistrationTest test = {
                        .n_open_failures = 1,
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                client->address_registration.max_retransmissions = 2;
                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_ERROR(dhcp6_client_update_address_registration_at(
                                client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), EIO);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                ASSERT_TRUE(registration->transaction_active);
                ASSERT_FALSE(registration->registration_attempted);
                ASSERT_EQ(registration->transmission_count, 1U);
                ASSERT_EQ(registration->retransmit_deadline_usec, now_usec + 900 * USEC_PER_MSEC);
                ASSERT_EQ(client->address_registration.fd, -EBADF);

                ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                                  client, &ia_na_address1, now_usec + USEC_PER_SEC), 1);
                ASSERT_EQ(test.n_open, 2U);
                ASSERT_EQ(test.n_sent, 1U);
                ASSERT_TRUE(registration->registration_attempted);
                ASSERT_EQ(registration->transmission_count, 2U);
        }

        {
                AddressRegistrationTest test = {
                        .n_send_failures = 1,
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_ERROR(dhcp6_client_update_address_registration_at(
                                client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), EIO);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                ASSERT_TRUE(registration->transaction_active);
                ASSERT_FALSE(registration->registration_attempted);
                ASSERT_EQ(registration->transmission_count, 1U);
                ASSERT_EQ(client->address_registration.fd, -EBADF);

                ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                                  client, &ia_na_address1, now_usec + USEC_PER_SEC), 1);
                ASSERT_EQ(test.n_open, 2U);
                ASSERT_EQ(test.n_send_attempts, 2U);
                ASSERT_EQ(test.n_sent, 1U);
                ASSERT_TRUE(registration->registration_attempted);
        }

        {
                AddressRegistrationTest test = {
                        .n_open_failures = UINT_MAX,
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                client->address_registration.max_retransmissions = 0;
                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_ERROR(dhcp6_client_update_address_registration_at(
                                client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), EIO);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                usec_t previous_deadline_usec = registration->retransmit_deadline_usec;

                for (unsigned i = 1; i <= 3; i++) {
                        ASSERT_ERROR(dhcp6_client_address_registration_retransmit_at(
                                        client, &ia_na_address1, now_usec + i * USEC_PER_SEC), EIO);
                        ASSERT_GT(registration->retransmit_deadline_usec, previous_deadline_usec);
                        previous_deadline_usec = registration->retransmit_deadline_usec;
                }

                ASSERT_TRUE(registration->transaction_active);
                ASSERT_FALSE(registration->registration_attempted);
                ASSERT_EQ(registration->transmission_count, 4U);
                ASSERT_EQ(test.n_sent, 0U);
        }

        {
                AddressRegistrationTest test = {
                        .n_open_failures = UINT_MAX,
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                client->address_registration.max_retransmissions = 3;
                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_ERROR(dhcp6_client_update_address_registration_at(
                                client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), EIO);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                for (unsigned i = 1; i <= 2; i++)
                        ASSERT_ERROR(dhcp6_client_address_registration_retransmit_at(
                                        client, &ia_na_address1, now_usec + i * USEC_PER_SEC), EIO);
                ASSERT_EQ(registration->transmission_count, 3U);
                ASSERT_TRUE(registration->transaction_active);

                ASSERT_EQ(dhcp6_client_address_registration_retransmit_at(
                                  client, &ia_na_address1, now_usec + 3 * USEC_PER_SEC), 0);
                ASSERT_EQ(registration->transmission_count, 3U);
                ASSERT_FALSE(registration->transaction_active);
                ASSERT_EQ(test.n_sent, 0U);
        }

        {
                AddressRegistrationTest test = {
                        .next_transaction_id = 0x123456,
                };
                _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                        test_address_registration_client_new(&test);

                client->address_registration.max_retransmissions = 0;
                ASSERT_EQ(dhcp6_client_address_registration_discover(
                                  client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
                ASSERT_EQ(dhcp6_client_update_address_registration_at(
                                  client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), 1);

                DHCP6AddressRegistration *registration = ASSERT_PTR(
                                test_address_registration_get(client, &ia_na_address1));
                registration->retransmit_time_usec = USEC_INFINITY;
                ASSERT_ERROR(dhcp6_client_address_registration_retransmit_at(
                                client, &ia_na_address1, now_usec + USEC_PER_SEC), ERANGE);
                ASSERT_FALSE(registration->transaction_active);
                ASSERT_EQ(registration->retransmit_deadline_usec, USEC_INFINITY);
        }
}

TEST(address_registration_timer_failure) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x123456,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const usec_t now_usec = now(CLOCK_BOOTTIME);

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, event, 0));
        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), 1);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &ia_na_address1));

        ASSERT_OK(sd_event_add_time(
                          event,
                          &registration->retransmit_event,
                          CLOCK_MONOTONIC,
                          USEC_INFINITY,
                          0,
                          /* callback= */ NULL,
                          /* userdata= */ NULL));

        ASSERT_ERROR(dhcp6_client_address_registration_discover(
                             client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), EINVAL);
        ASSERT_FALSE(registration->transaction_active);
        ASSERT_FALSE(registration->registration_attempted);
        ASSERT_EQ(registration->retransmit_deadline_usec, USEC_INFINITY);
        ASSERT_EQ(sd_event_source_get_enabled(registration->retransmit_event, /* ret= */ NULL), 0);
        ASSERT_EQ(test.n_send_attempts, 0U);

        registration->retransmit_event = sd_event_source_unref(registration->retransmit_event);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), 1);
        ASSERT_TRUE(registration->transaction_active);
        ASSERT_NOT_NULL(registration->retransmit_event);
        ASSERT_EQ(test.n_sent, 1U);
}

TEST(address_registration_mrc_without_successful_send) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x123456,
                .n_send_failures = UINT_MAX,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        const usec_t now_usec = now(CLOCK_BOOTTIME);

        ASSERT_OK(sd_event_new(&event));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, event, 0));

        client->address_registration.max_retransmissions = 2;
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
        ASSERT_ERROR(dhcp6_client_update_address_registration_at(
                             client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), EIO);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &ia_na_address1));
        ASSERT_TRUE(registration->transaction_active);

        ASSERT_ERROR(dhcp6_client_address_registration_retransmit_at(
                             client, &ia_na_address1, now_usec + USEC_PER_SEC), EIO);
        ASSERT_EQ(registration->transmission_count, 2U);

        ASSERT_OK(dhcp6_client_address_registration_retransmit_at(
                          client, &ia_na_address1, now_usec + 2 * USEC_PER_SEC));
        ASSERT_FALSE(registration->transaction_active);
        ASSERT_FALSE(registration->registration_attempted);
        ASSERT_EQ(test.n_sent, 0U);
}

TEST(address_registration_event_migration) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x123456,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);
        _cleanup_(sd_event_unrefp) sd_event *event_old = NULL, *event_new = NULL;
        const usec_t now_usec = now(CLOCK_BOOTTIME);

        ASSERT_OK(sd_event_new(&event_old));
        ASSERT_OK(sd_event_new(&event_new));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, event_old, 10));
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, now_usec), 1);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &ia_na_address1));
        const usec_t retransmit_deadline_usec = registration->retransmit_deadline_usec;
        ASSERT_TRUE(sd_event_source_get_event(client->address_registration.receive_event) == event_old);
        ASSERT_TRUE(sd_event_source_get_event(registration->retransmit_event) == event_old);

        ASSERT_OK(sd_dhcp6_client_stop(client));
        ASSERT_OK(sd_dhcp6_client_detach_event(client));
        ASSERT_NULL(client->address_registration.receive_event);
        ASSERT_NULL(registration->retransmit_event);
        ASSERT_GE(client->address_registration.fd, 0);
        ASSERT_EQ(registration->retransmit_deadline_usec, retransmit_deadline_usec);

        ASSERT_OK(sd_dhcp6_client_attach_event(client, event_new, 20));
        ASSERT_TRUE(sd_event_source_get_event(client->address_registration.receive_event) == event_new);
        ASSERT_TRUE(sd_event_source_get_event(registration->retransmit_event) == event_new);
        ASSERT_EQ(registration->retransmit_deadline_usec, retransmit_deadline_usec);

        ASSERT_OK(sd_dhcp6_client_set_local_address(client, &local_address));
        ASSERT_OK(sd_dhcp6_client_set_information_request(client, true));
        ASSERT_OK(sd_dhcp6_client_start(client));
        ASSERT_TRUE(sd_event_source_get_event(client->receive_message) == event_new);
        ASSERT_OK(sd_dhcp6_client_stop(client));

        test_fd[1] = safe_close(test_fd[1]);
        test_client_sent_message_count = 0;
}

TEST(address_registration_discovery_starts_existing) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x123456,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, 0), 1);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 1U);
        ASSERT_EQ(test.n_open, 0U);
        ASSERT_EQ(test.n_sent, 0U);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_ADVERTISE, /* advertised= */ true), 1);
        ASSERT_EQ(test.n_open, 1U);
        ASSERT_EQ(test.n_sent, 1U);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &ia_na_address1));
        ASSERT_TRUE(registration->transaction_active);

        dhcp6_client_address_registration_reset(client);
        ASSERT_FALSE(client->address_registration.supported);
        ASSERT_FALSE(registration->transaction_active);
        ASSERT_FALSE(registration->registration_attempted);
        ASSERT_EQ(client->address_registration.fd, -EBADF);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 1U);

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_EQ(test.n_open, 2U);
        ASSERT_EQ(test.n_sent, 2U);
        ASSERT_NE(test.sent[0].transaction_id, test.sent[1].transaction_id);

        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, 0, 0, 0), 0);
        ASSERT_EQ(hashmap_size(client->address_registration.registrations), 0U);
}

TEST(address_registration_retransmission_time) {
        ASSERT_EQ(dhcp6_address_registration_initial_retransmission_time(USEC_PER_SEC, 0),
                  900 * USEC_PER_MSEC);
        ASSERT_EQ(dhcp6_address_registration_initial_retransmission_time(
                          USEC_PER_SEC, 200 * USEC_PER_MSEC),
                  1100 * USEC_PER_MSEC);
        ASSERT_EQ(dhcp6_address_registration_next_retransmission_time(USEC_PER_SEC, 0),
                  1900 * USEC_PER_MSEC);
        ASSERT_EQ(dhcp6_address_registration_next_retransmission_time(
                          USEC_PER_SEC, 200 * USEC_PER_MSEC),
                  2100 * USEC_PER_MSEC);
}

TEST(address_registration_reply_validation) {
        AddressRegistrationTest test = {
                .next_transaction_id = 0x654321,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);
        _cleanup_free_ uint8_t *reply = NULL;
        const struct sockaddr_in6 sender = {
                .sin6_family = AF_INET6,
                .sin6_addr = local_address,
                .sin6_port = htobe16(DHCP6_PORT_SERVER),
        };
        size_t len;

        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 1);
        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, 0), 1);

        DHCP6AddressRegistration *registration = ASSERT_PTR(
                        test_address_registration_get(client, &ia_na_address1));
        const be32_t transaction_id = registration->transaction_id;

        reply = test_address_registration_reply(
                        transaction_id, &ia_na_address1, 0, sizeof(struct iaaddr), &len);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);

        reply = mfree(reply);
        reply = test_address_registration_reply(
                        transaction_id, &ia_na_address1, 2, sizeof(struct iaaddr), &len);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);

        reply = mfree(reply);
        reply = test_address_registration_reply(
                        transaction_id, &ia_na_address1, 1, sizeof(struct iaaddr) - 1, &len);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);

        reply = mfree(reply);
        reply = test_address_registration_reply(
                        transaction_id, &ia_na_address2, 1, sizeof(struct iaaddr), &len);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);

        reply = mfree(reply);
        reply = test_address_registration_reply(
                        transaction_id, &ia_na_address1, 1, sizeof(struct iaaddr), &len);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, true, 0), 0);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address2, test_ifindex, false, 0), 0);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex + 1, false, 0), 0);

        struct sockaddr_in6 wrong_sender = sender;
        wrong_sender.sin6_port = htobe16(DHCP6_PORT_CLIENT);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &wrong_sender, &ia_na_address1, test_ifindex, false, 0), 0);

        ((DHCP6Message*) reply)->transaction_id ^= htobe32(1);
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);
        ((DHCP6Message*) reply)->transaction_id ^= htobe32(1);
        ((DHCP6Message*) reply)->type = DHCP6_MESSAGE_REPLY;
        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);
        ((DHCP6Message*) reply)->type = DHCP6_MESSAGE_ADDR_REG_REPLY;

        ASSERT_LE(len, sizeof(test.receive_packet));
        memcpy(test.receive_packet, reply, len);
        test.receive_len = len;
        test.receive_sender = sender;
        test.receive_destination = ia_na_address1;
        test.receive_ifindex = test_ifindex;
        ASSERT_OK(dhcp6_client_receive_address_registration_reply(client));
        ASSERT_EQ(test.n_received, 1U);
        ASSERT_FALSE(registration->transaction_active);

        ASSERT_EQ(dhcp6_client_process_address_registration_reply_at(
                          client, reply, len, &sender, &ia_na_address1, test_ifindex, false, 0), 0);
}

TEST(address_registration_disabled) {
        AddressRegistrationTest test = {
                .next_transaction_id = 1,
        };
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client =
                test_address_registration_client_new(&test);

        ASSERT_OK(dhcp6_client_set_address_registration_enabled(client, false));
        ASSERT_EQ(dhcp6_client_address_registration_discover(
                          client, DHCP6_MESSAGE_REPLY, /* advertised= */ true), 0);
        ASSERT_EQ(dhcp6_client_update_address_registration_at(
                          client, &ia_na_address1, USEC_INFINITY, USEC_INFINITY, 0), 1);
        ASSERT_EQ(test.n_open, 0U);
        ASSERT_EQ(test.n_sent, 0U);
}

static void test_client_verify_information_request(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        assert_se(len == sizeof(msg_information_request));
        /* The elapsed time value is not deterministic. Skip it. */
        assert_se(memcmp(msg, msg_information_request, len - sizeof(be16_t)) == 0);
}

static void test_client_verify_solicit(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        assert_se(len == sizeof(msg_solicit));
        /* The elapsed time value is not deterministic. Skip it. */
        assert_se(memcmp(msg, msg_solicit, len - sizeof(be16_t)) == 0);
}

static void test_client_verify_release(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        assert_se(len == sizeof(msg_release));
        assert_se(msg->type == DHCP6_MESSAGE_RELEASE);
        /* The transaction ID and elapsed time value are not deterministic. Skip them. */
        assert_se(memcmp(msg->options, msg_release + offsetof(DHCP6Message, options),
                         len - offsetof(DHCP6Message, options) - sizeof(be16_t)) == 0);
}

static void test_client_verify_request(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        assert_se(len == sizeof(msg_request));
        assert_se(msg->type == DHCP6_MESSAGE_REQUEST);
        /* The transaction ID and elapsed time value are not deterministic. Skip them. */
        assert_se(memcmp(msg->options, msg_request + offsetof(DHCP6Message, options),
                         len - offsetof(DHCP6Message, options) - sizeof(be16_t)) == 0);
}

static void test_lease_common(sd_dhcp6_client *client) {
        sd_dhcp6_lease *lease;
        sd_dhcp6_option **suboption;
        const struct in6_addr *addrs;
        const char *str;
        char **strv;
        uint8_t *id;
        size_t len;

        assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);

        assert_se(dhcp6_lease_get_clientid(lease, &id, &len) >= 0);
        assert_se(memcmp_nn(id, len, client_id, sizeof(client_id)) == 0);

        assert_se(sd_dhcp6_lease_get_domains(lease, &strv) == 1);
        assert_se(streq(strv[0], "lab.intra"));
        assert_se(!strv[1]);

        assert_se(sd_dhcp6_lease_get_fqdn(lease, &str) >= 0);
        assert_se(streq(str, "client.lab.intra"));

        assert_se(sd_dhcp6_lease_get_dns(lease, &addrs) == 2);
        assert_se(in6_addr_equal(&addrs[0], &dns1));
        assert_se(in6_addr_equal(&addrs[1], &dns2));

        assert_se(sd_dhcp6_lease_get_ntp_addrs(lease, &addrs) == 2);
        assert_se(in6_addr_equal(&addrs[0], &ntp1));
        assert_se(in6_addr_equal(&addrs[1], &ntp2));

        assert_se(sd_dhcp6_lease_get_ntp_fqdn(lease, &strv) == 1);
        assert_se(streq(strv[0], "ntp.intra"));
        assert_se(!strv[1]);

        assert_se(sd_dhcp6_lease_get_sip_addrs(lease, &addrs) == 2);
        assert_se(in6_addr_equal(&addrs[0], &sip1));
        assert_se(in6_addr_equal(&addrs[1], &sip2));

        assert_se(sd_dhcp6_lease_get_sip_domains(lease, &strv) == 1);
        assert_se(streq(strv[0], "sip.intra"));
        assert_se(!strv[1]);

        assert_se(lease->sntp_count == 2);
        assert_se(in6_addr_equal(&lease->sntp[0], &sntp1));
        assert_se(in6_addr_equal(&lease->sntp[1], &sntp2));

        assert_se(sd_dhcp6_lease_get_vendor_options(lease, &suboption) > 0);
        assert_se((*suboption)->enterprise_identifier == vendor_suboption.enterprise_identifier);
        assert_se((*suboption)->option == vendor_suboption.option);
        assert_se(*(uint8_t*)(*suboption)->data == *(uint8_t*)vendor_suboption.data);
}

static void test_lease_managed(sd_dhcp6_client *client) {
        sd_dhcp6_lease *lease;
        struct in6_addr addr;
        usec_t lt_pref, lt_valid;
        uint8_t *id, prefixlen;
        size_t len;

        assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);

        assert_se(dhcp6_lease_get_serverid(lease, &id, &len) >= 0);
        assert_se(memcmp_nn(id, len, server_id, sizeof(server_id)) == 0);

        assert_se(sd_dhcp6_lease_has_address(lease));
        assert_se(sd_dhcp6_lease_has_pd_prefix(lease));

        for (unsigned i = 0; i < 2; i++) {
                assert_se(sd_dhcp6_lease_address_iterator_reset(lease));
                assert_se(sd_dhcp6_lease_get_address(lease, &addr) >= 0);
                assert_se(sd_dhcp6_lease_get_address_lifetime(lease, &lt_pref, &lt_valid) >= 0);
                assert_se(in6_addr_equal(&addr, &ia_na_address1));
                assert_se(lt_pref == 150 * USEC_PER_SEC);
                assert_se(lt_valid == 180 * USEC_PER_SEC);
                assert_se(sd_dhcp6_lease_address_iterator_next(lease));
                assert_se(sd_dhcp6_lease_get_address(lease, &addr) >= 0);
                assert_se(sd_dhcp6_lease_get_address_lifetime(lease, &lt_pref, &lt_valid) >= 0);
                assert_se(in6_addr_equal(&addr, &ia_na_address2));
                assert_se(lt_pref == 150 * USEC_PER_SEC);
                assert_se(lt_valid == 180 * USEC_PER_SEC);
                assert_se(!sd_dhcp6_lease_address_iterator_next(lease));

                assert_se(sd_dhcp6_lease_pd_iterator_reset(lease));
                assert_se(sd_dhcp6_lease_get_pd_prefix(lease, &addr, &prefixlen) >= 0);
                assert_se(sd_dhcp6_lease_get_pd_lifetime(lease, &lt_pref, &lt_valid) >= 0);
                assert_se(in6_addr_equal(&addr, &ia_pd_prefix1));
                assert_se(prefixlen == 64);
                assert_se(lt_pref == 150 * USEC_PER_SEC);
                assert_se(lt_valid == 180 * USEC_PER_SEC);
                assert_se(sd_dhcp6_lease_pd_iterator_next(lease));
                assert_se(sd_dhcp6_lease_get_pd_prefix(lease, &addr, &prefixlen) >= 0);
                assert_se(sd_dhcp6_lease_get_pd_lifetime(lease, &lt_pref, &lt_valid) >= 0);
                assert_se(in6_addr_equal(&addr, &ia_pd_prefix2));
                assert_se(prefixlen == 64);
                assert_se(lt_pref == 150 * USEC_PER_SEC);
                assert_se(lt_valid == 180 * USEC_PER_SEC);
                assert_se(!sd_dhcp6_lease_pd_iterator_next(lease));
        }

        test_lease_common(client);
}

static void test_client_callback(sd_dhcp6_client *client, int event, void *userdata) {
        switch (event) {
        case SD_DHCP6_CLIENT_EVENT_STOP:
                log_debug("/* %s (event=stop) */", __func__);
                return;

        case SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST:
                log_debug("/* %s (event=information-request) */", __func__);

                assert_se(test_client_sent_message_count == 1);

                test_lease_common(client);

                assert_se(sd_dhcp6_client_set_information_request(client, false) >= 0);
                assert_se(sd_dhcp6_client_start(client) >= 0);
                assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message*) msg_advertise)->transaction_id) >= 0);
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                log_debug("/* %s (event=ip-acquire) */", __func__);

                assert_se(IN_SET(test_client_sent_message_count, 3, 5));

                test_lease_managed(client);

                switch (test_client_sent_message_count) {
                case 3:
                        assert_se(sd_dhcp6_client_stop(client) >= 0);
                        assert_se(sd_dhcp6_client_start(client) >= 0);
                        assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message*) msg_reply)->transaction_id) >= 0);
                        break;

                case 5:
                        assert_se(sd_event_exit(sd_dhcp6_client_get_event(client), 0) >= 0);
                        break;

                default:
                        assert_not_reached();
                }

                break;

        case DHCP6_CLIENT_EVENT_TEST_ADVERTISED: {
                sd_dhcp6_lease *lease;
                uint8_t preference;

                log_debug("/* %s (event=test-advertised) */", __func__);

                assert_se(test_client_sent_message_count == 2);

                test_lease_managed(client);

                assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);
                assert_se(dhcp6_lease_get_preference(lease, &preference) >= 0);
                assert_se(preference == 0xff);

                assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message*) msg_reply)->transaction_id) >= 0);
                break;
        }
        default:
                assert_not_reached();
        }
}

int dhcp6_network_send_udp_socket(int s, const struct in6_addr *a, const void *packet, size_t len) {
        log_debug("/* %s(count=%u) */", __func__, test_client_sent_message_count);

        assert_se(a);
        assert_se(in6_addr_equal(a, &mcast_address));
        assert_se(packet);
        assert_se(len >= sizeof(DHCP6Message));

        if (client_oro_test) {
                test_client_verify_oro(
                                packet,
                                len,
                                client_oro_test->expect_n_address_registration,
                                client_oro_test->n_automatic_options);
                return len;
        }

        switch (test_client_sent_message_count) {
        case 0:
                test_client_verify_information_request(packet, len);
                assert_se(write(test_fd[1], msg_reply, sizeof(msg_reply)) == sizeof(msg_reply));
                break;

        case 1:
                test_client_verify_solicit(packet, len);
                assert_se(write(test_fd[1], msg_advertise, sizeof(msg_advertise)) == sizeof(msg_advertise));
                break;

        case 2:
                test_client_callback(client_ref, DHCP6_CLIENT_EVENT_TEST_ADVERTISED, NULL);
                test_client_verify_request(packet, len);
                assert_se(write(test_fd[1], msg_reply, sizeof(msg_reply)) == sizeof(msg_reply));
                break;

        case 3:
                test_client_verify_release(packet, len);
                /* when stopping, dhcp6 client doesn't wait for release server reply */
                assert_se(write(test_fd[1], msg_reply, sizeof(msg_reply)) == sizeof(msg_reply));
                break;

        case 4:
                test_client_verify_solicit(packet, len);
                assert_se(write(test_fd[1], msg_reply, sizeof(msg_reply)) == sizeof(msg_reply));
                break;

        default:
                assert_not_reached();
        }

        test_client_sent_message_count++;
        return len;
}

int dhcp6_network_bind_udp_socket(int ifindex, const struct in6_addr *a) {
        assert_se(ifindex == test_ifindex);
        assert_se(a);
        assert_se(in6_addr_equal(a, &local_address));

        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);
        return TAKE_FD(test_fd[0]);
}

TEST(dhcp6_client) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        default_address_registration_test = (AddressRegistrationTest) {};
        address_registration_test = &default_address_registration_test;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, 0,
                                             NULL, INT_TO_PTR(-ETIMEDOUT)) >= 0);

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, test_ifindex) == 0);
        assert_se(sd_dhcp6_client_set_local_address(client, &local_address) >= 0);
        assert_se(sd_dhcp6_client_set_fqdn(client, "host.lab.intra") >= 0);
        assert_se(sd_dhcp6_client_set_iaid(client, unaligned_read_be32((uint8_t[]) { IA_ID_BYTES })) >= 0);
        assert_se(sd_dhcp6_client_set_send_release(client, true) >= 0);

        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER) >= 0);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVER) >= 0);

        assert_se(sd_dhcp6_client_set_information_request(client, true) >= 0);
        assert_se(sd_dhcp6_client_set_callback(client, test_client_callback, NULL) >= 0);

        assert_se(sd_dhcp6_client_start(client) >= 0);

        assert_se(dhcp6_client_set_transaction_id(client, ((const DHCP6Message*) msg_reply)->transaction_id) >= 0);

        assert_se(client_ref = sd_dhcp6_client_ref(client));

        assert_se(sd_event_loop(e) >= 0);

        assert_se(test_client_sent_message_count == 5);

        assert_se(!sd_dhcp6_client_unref(client_ref));
        test_fd[1] = safe_close(test_fd[1]);
}

static int intro(void) {
        assert_se(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", 1) >= 0);
        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
