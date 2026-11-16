/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-dhcp6-protocol.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "hmac.h"
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
static bool test_reconfigure = false;
static bool test_reconfigure_stateless = false;
static unsigned test_reconfigure_count = 0;

TEST(client_basic) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        int v;

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_NOT_NULL(client);

        ASSERT_OK_ZERO(sd_dhcp6_client_set_ifindex(client, 15));
        ASSERT_OK(sd_dhcp6_client_set_ifindex(client, 42));

        ASSERT_OK(sd_dhcp6_client_set_mac(client, mac.ether_addr_octet, sizeof(mac), ARPHRD_ETHER));

        ASSERT_OK_EQ(sd_dhcp6_client_set_fqdn(client, "host"), 1);
        ASSERT_OK_EQ(sd_dhcp6_client_set_fqdn(client, "host.domain"), 1);
        ASSERT_OK_EQ(sd_dhcp6_client_set_fqdn(client, /* fqdn= */ NULL), 1);
        ASSERT_ERROR(sd_dhcp6_client_set_fqdn(client, "~host"), EINVAL);
        ASSERT_ERROR(sd_dhcp6_client_set_fqdn(client, "~host.domain"), EINVAL);

        ASSERT_ERROR(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_CLIENTID), EINVAL);
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_ADDRESS));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SIP_SERVER_DOMAIN_NAME));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_VENDOR_OPTS));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN));
        ASSERT_ERROR(sd_dhcp6_client_set_request_option(client, 10), EINVAL);
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NIS_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NISP_SERVER));
        ASSERT_ERROR(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NIS_SERVER), EEXIST);
        ASSERT_ERROR(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NISP_SERVER), EEXIST);

        ASSERT_OK(sd_dhcp6_client_set_information_request(client, 1));
        v = 0;
        ASSERT_OK(sd_dhcp6_client_get_information_request(client, &v));
        ASSERT_TRUE(v);
        ASSERT_OK(sd_dhcp6_client_set_information_request(client, /* enabled= */ 0));
        v = 42;
        ASSERT_OK(sd_dhcp6_client_get_information_request(client, &v));
        ASSERT_FALSE(v);

        v = 0;
        ASSERT_OK(sd_dhcp6_client_get_address_request(client, &v));
        ASSERT_TRUE(v);
        v = 0;
        ASSERT_OK(sd_dhcp6_client_set_address_request(client, 1));
        ASSERT_OK(sd_dhcp6_client_get_address_request(client, &v));
        ASSERT_TRUE(v);
        v = 42;
        ASSERT_OK(sd_dhcp6_client_set_address_request(client, 1));
        ASSERT_OK(sd_dhcp6_client_get_address_request(client, &v));
        ASSERT_TRUE(v);

        ASSERT_OK(sd_dhcp6_client_set_address_request(client, 1));
        ASSERT_OK(sd_dhcp6_client_set_prefix_delegation(client, 1));
        v = 0;
        ASSERT_OK(sd_dhcp6_client_get_address_request(client, &v));
        ASSERT_TRUE(v);
        v = 0;
        ASSERT_OK(sd_dhcp6_client_get_prefix_delegation(client, &v));
        ASSERT_TRUE(v);

        ASSERT_OK(sd_dhcp6_client_set_callback(client, /* cb= */ NULL, /* userdata= */ NULL));

        ASSERT_OK(sd_dhcp6_client_detach_event(client));
}

TEST(parse_domain) {
        _cleanup_free_ char *domain = NULL;
        _cleanup_strv_free_ char **list = NULL;
        uint8_t *data;

        data = (uint8_t []) { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
        ASSERT_OK(dhcp6_option_parse_domainname(data, 13, &domain));
        ASSERT_NOT_NULL(domain);
        ASSERT_STREQ(domain, "example.com");
        domain = mfree(domain);

        data = (uint8_t []) { 4, 't', 'e', 's', 't' };
        ASSERT_OK(dhcp6_option_parse_domainname(data, 5, &domain));
        ASSERT_STREQ(domain, "test");
        domain = mfree(domain);

        data = (uint8_t []) { 0 };
        ASSERT_ERROR(dhcp6_option_parse_domainname(data, 1, &domain), ENODATA);

        data = (uint8_t []) { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
                              6, 'f', 'o', 'o', 'b', 'a', 'r', 0 };
        ASSERT_OK(dhcp6_option_parse_domainname_list(data, 21, &list));
        ASSERT_NOT_NULL(list);
        ASSERT_STREQ(list[0], "example.com");
        ASSERT_STREQ(list[1], "foobar");
        ASSERT_NULL(list[2]);
        list = strv_free(list);

        data = (uint8_t []) { 1, 'a', 0, 20, 'b', 'c' };
        ASSERT_ERROR(dhcp6_option_parse_domainname_list(data, 6, &list), EINVAL);

        data = (uint8_t []) { 1, 'a', 0, 20, 'b', 'c', 0 };
        ASSERT_ERROR(dhcp6_option_parse_domainname_list(data, 7, &list), EMSGSIZE);

        data = (uint8_t []) { 0 , 0 };
        ASSERT_ERROR(dhcp6_option_parse_domainname_list(data, 2, &list), EBADMSG);
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

        ASSERT_EQ(sizeof(packet), sizeof(result));

        offset = 0;
        ASSERT_ERROR(dhcp6_option_parse(packet, /* buflen= */ 0, &offset, &optcode, &optlen, &optval), EBADMSG);

        offset = 3;
        ASSERT_ERROR(dhcp6_option_parse(packet, /* buflen= */ 0, &offset, &optcode, &optlen, &optval), EBADMSG);

        /* Tests for reading unaligned data. */
        ASSERT_NOT_NULL(buf = new(uint8_t, sizeof(packet)));
        for (size_t i = 0; i <= 7; i++) {
                memcpy(buf, packet + i, sizeof(packet) - i);
                offset = 7 - i;
                ASSERT_OK(dhcp6_option_parse(buf, sizeof(packet), &offset, &optcode, &optlen, &optval));

                ASSERT_EQ(optcode, SD_DHCP6_OPTION_ORO);
                ASSERT_EQ(optlen, 7u);
                ASSERT_PTR_EQ(optval, buf + 11 - i);
        }

        offset = 7;
        ASSERT_OK(dhcp6_option_parse(packet, sizeof(packet), &offset, &optcode, &optlen, &optval));

        ASSERT_EQ(optcode, SD_DHCP6_OPTION_ORO);
        ASSERT_EQ(optlen, 7u);
        ASSERT_PTR_EQ(optval, packet + 11);

        free(buf);
        ASSERT_NOT_NULL(buf = memdup(result, sizeof(result)));
        pos = 7;
        ASSERT_OK(dhcp6_option_append(&buf, &pos, optcode, optlen, optval));

        ASSERT_OK(dhcp6_option_parse(packet, sizeof(packet), &offset, &optcode, &optlen, &optval));

        ASSERT_EQ(optcode, SD_DHCP6_OPTION_VENDOR_CLASS);
        ASSERT_EQ(optlen, 9u);
        ASSERT_PTR_EQ(optval, packet + 22);

        ASSERT_OK(dhcp6_option_append(&buf, &pos, optcode, optlen, optval));

        ASSERT_MEMEQ(packet, buf, sizeof(packet));
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
        ASSERT_EQ(sizeof(option1), sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(/* client= */ NULL, /* iaid= */ 0, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, ENOANO);

        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, EINVAL);

        option->len = htobe16(17);
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, EBADMSG);

        option->len = htobe16(sizeof(DHCP6Option));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, EBADMSG);

        option = (DHCP6Option*) option2;
        ASSERT_EQ(sizeof(option2), sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, ENODATA);

        option = (DHCP6Option*) option3;
        ASSERT_EQ(sizeof(option3), sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(ia);
        ASSERT_NOT_NULL(ia->addresses);
        ia = dhcp6_ia_free(ia);

        option = (DHCP6Option*) option4;
        ASSERT_EQ(sizeof(option4), sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(ia);
        ASSERT_NOT_NULL(ia->addresses);
        ASSERT_EQ(be32toh(ia->header.id), unaligned_read_be32(&option4[4]));
        ASSERT_EQ(be32toh(ia->header.lifetime_t1), unaligned_read_be32(&option4[8]));
        ASSERT_EQ(be32toh(ia->header.lifetime_t2), unaligned_read_be32(&option4[12]));
        ia = dhcp6_ia_free(ia);

        option = (DHCP6Option*) option5;
        ASSERT_EQ(sizeof(option5), sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_OK(r);
        ASSERT_NOT_NULL(ia);
        ASSERT_NOT_NULL(ia->addresses);
        ia = dhcp6_ia_free(ia);

        /* An IA_PD whose only prefix carries an invalid (zero) prefix length must be refused, leaving no
         * valid prefix behind. */
        option = (DHCP6Option*) option6;
        ASSERT_EQ(sizeof(option6), sizeof(DHCP6Option) + be16toh(option->len));
        r = dhcp6_option_parse_ia(/* client= */ NULL, iaid, be16toh(option->code), be16toh(option->len), option->data, &ia);
        ASSERT_ERROR(r, ENODATA);
        ASSERT_NULL(ia);
}

TEST(lease_timezone) {
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        const char *str;

        ASSERT_OK(dhcp6_lease_new(&lease));

        /* "UTC" in the main test messages bypasses the tzfile check in
         * verify_timezone(); exercise the validation with invalid inputs. */
        ASSERT_ERROR(dhcp6_lease_set_timezone(lease, (const uint8_t *) "", /* optlen= */ 0), EINVAL);
        ASSERT_ERROR(dhcp6_lease_set_timezone(lease, (const uint8_t *) "UTC\0", 4), EINVAL);
        ASSERT_ERROR(dhcp6_lease_set_timezone(lease, (const uint8_t *) "/etc/passwd", 11), EINVAL);
        ASSERT_ERROR(dhcp6_lease_set_timezone(lease, (const uint8_t *) "../passwd", 9), EINVAL);
        ASSERT_ERROR(sd_dhcp6_lease_get_timezone(lease, &str), ENODATA);

        ASSERT_OK(dhcp6_lease_set_timezone(lease, (const uint8_t *) "UTC", 3));
        ASSERT_OK(sd_dhcp6_lease_get_timezone(lease, &str));
        ASSERT_STREQ(str, "UTC");
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

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_set_iaid(client, 0xcc59117b));
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(client, 2, duid, sizeof(duid)));

        ASSERT_OK(dhcp6_lease_new_from_message(client, (const DHCP6Message*) msg, sizeof(msg),
                                               /* timestamp= */ NULL, /* server_address= */ NULL, &lease));
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

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_set_iaid(client, 0xaabbccdd));
        ASSERT_OK(sd_dhcp6_client_set_duid_raw(client, 2, duid, sizeof(duid)));

        ASSERT_OK(dhcp6_lease_new_from_message(client, (const DHCP6Message*) msg, sizeof(msg),
                                               /* timestamp= */ NULL, /* server_address= */ NULL, &lease));
}

static const uint8_t msg_information_request[] = {
        /* Message type */
        DHCP6_MESSAGE_INFORMATION_REQUEST,
        /* Transaction ID */
        0x0f, 0xb4, 0xe5,
        /* MUD URL */
        /* ORO */
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x0c,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_INFORMATION_REFRESH_TIME,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
        0x00, SD_DHCP6_OPTION_INF_MAX_RT,
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
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x0a,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
        0x00, SD_DHCP6_OPTION_SOL_MAX_RT,
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
        0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x08,
        0x00, SD_DHCP6_OPTION_DNS_SERVER,
        0x00, SD_DHCP6_OPTION_DOMAIN,
        0x00, SD_DHCP6_OPTION_SNTP_SERVER,
        0x00, SD_DHCP6_OPTION_NTP_SERVER,
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
        /* Time Zone (TZ Database name) */
        0x00, SD_DHCP6_OPTION_TZDB_TIMEZONE, 0x00, 0x03,
        'U', 'T', 'C',
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
        /* Time Zone (TZ Database name) */
        0x00, SD_DHCP6_OPTION_TZDB_TIMEZONE, 0x00, 0x03,
        'U', 'T', 'C',
        /* Vendor specific options */
        0x00, SD_DHCP6_OPTION_VENDOR_OPTS, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x20, 0x00, 0xf7, 0x00, 0x01, VENDOR_SUBOPTION_BYTES,
};

static void test_client_verify_information_request(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        ASSERT_EQ(len, sizeof(msg_information_request));
        /* The elapsed time value is not deterministic. Skip it. */
        ASSERT_MEMEQ(msg, msg_information_request, len - sizeof(be16_t));
}

static void test_client_verify_solicit(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        ASSERT_EQ(len, sizeof(msg_solicit));
        /* The elapsed time value is not deterministic. Skip it. */
        ASSERT_MEMEQ(msg, msg_solicit, len - sizeof(be16_t));
}

/* The FQDN set while the client is running, in the wire format. */
static const uint8_t new_fqdn[] = {
        0x04, 'n', 'e', 'x', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
};

static void test_client_verify_solicit_with_new_fqdn(const DHCP6Message *msg, size_t len) {
        static const uint8_t old_fqdn[] = {
                0x04, 'h', 'o', 's', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        };
        uint8_t expected[sizeof(msg_solicit)];
        uint8_t *p;

        log_debug("/* %s */", __func__);

        /* Same as msg_solicit, but with the FQDN set while the client was running. */
        memcpy(expected, msg_solicit, sizeof(expected));
        p = memmem_safe(expected, sizeof(expected), old_fqdn, sizeof(old_fqdn));
        ASSERT_NOT_NULL(p);
        memcpy(p, new_fqdn, sizeof(new_fqdn));

        ASSERT_EQ(len, sizeof(expected));
        /* The elapsed time value is not deterministic. Skip it. */
        ASSERT_MEMEQ(msg, expected, len - sizeof(be16_t));
}

static void test_client_verify_renew_with_new_fqdn(const DHCP6Message *msg, size_t len) {
        const uint8_t *options = msg->options;
        size_t options_len = len - offsetof(DHCP6Message, options);

        log_debug("/* %s */", __func__);

        ASSERT_EQ(msg->type, DHCP6_MESSAGE_RENEW);
        /* RENEW is sent to the server which provided the lease, and carries the new FQDN. */
        ASSERT_NOT_NULL(memmem_safe(options, options_len, server_id, sizeof(server_id)));
        ASSERT_NOT_NULL(memmem_safe(options, options_len, new_fqdn, sizeof(new_fqdn)));
}

static void test_client_verify_release(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        ASSERT_EQ(len, sizeof(msg_release));
        ASSERT_EQ(msg->type, DHCP6_MESSAGE_RELEASE);
        /* The transaction ID and elapsed time value are not deterministic. Skip them. */
        ASSERT_MEMEQ(msg->options, msg_release + offsetof(DHCP6Message, options),
                     len - offsetof(DHCP6Message, options) - sizeof(be16_t));
}

static void test_client_verify_request(const DHCP6Message *msg, size_t len) {
        log_debug("/* %s */", __func__);

        ASSERT_EQ(len, sizeof(msg_request));
        ASSERT_EQ(msg->type, DHCP6_MESSAGE_REQUEST);
        /* The transaction ID and elapsed time value are not deterministic. Skip them. */
        ASSERT_MEMEQ(msg->options, msg_request + offsetof(DHCP6Message, options),
                     len - offsetof(DHCP6Message, options) - sizeof(be16_t));
}

static void test_lease_common(sd_dhcp6_client *client) {
        sd_dhcp6_lease *lease;
        sd_dhcp6_option **suboption;
        const struct in6_addr *addrs;
        const char *str;
        char **strv;
        uint8_t *id;
        size_t len;

        ASSERT_OK(sd_dhcp6_client_get_lease(client, &lease));

        ASSERT_OK(dhcp6_lease_get_clientid(lease, &id, &len));
        ASSERT_MEMEQ_NN(id, len, client_id, sizeof(client_id));

        ASSERT_OK_EQ(sd_dhcp6_lease_get_domains(lease, &strv), 1);
        ASSERT_STREQ(strv[0], "lab.intra");
        ASSERT_NULL(strv[1]);

        ASSERT_OK(sd_dhcp6_lease_get_fqdn(lease, &str));
        ASSERT_STREQ(str, "client.lab.intra");

        ASSERT_OK(sd_dhcp6_lease_get_timezone(lease, &str));
        ASSERT_STREQ(str, "UTC");

        ASSERT_OK_EQ(sd_dhcp6_lease_get_dns(lease, &addrs), 2);
        ASSERT_TRUE(in6_addr_equal(&addrs[0], &dns1));
        ASSERT_TRUE(in6_addr_equal(&addrs[1], &dns2));

        ASSERT_OK_EQ(sd_dhcp6_lease_get_ntp_addrs(lease, &addrs), 2);
        ASSERT_TRUE(in6_addr_equal(&addrs[0], &ntp1));
        ASSERT_TRUE(in6_addr_equal(&addrs[1], &ntp2));

        ASSERT_OK_EQ(sd_dhcp6_lease_get_ntp_fqdn(lease, &strv), 1);
        ASSERT_STREQ(strv[0], "ntp.intra");
        ASSERT_NULL(strv[1]);

        ASSERT_OK_EQ(sd_dhcp6_lease_get_sip_addrs(lease, &addrs), 2);
        ASSERT_TRUE(in6_addr_equal(&addrs[0], &sip1));
        ASSERT_TRUE(in6_addr_equal(&addrs[1], &sip2));

        ASSERT_OK_EQ(sd_dhcp6_lease_get_sip_domains(lease, &strv), 1);
        ASSERT_STREQ(strv[0], "sip.intra");
        ASSERT_NULL(strv[1]);

        ASSERT_EQ(lease->sntp_count, 2u);
        ASSERT_TRUE(in6_addr_equal(&lease->sntp[0], &sntp1));
        ASSERT_TRUE(in6_addr_equal(&lease->sntp[1], &sntp2));

        ASSERT_OK_EQ(sd_dhcp6_lease_get_vendor_options(lease, &suboption), 1);
        ASSERT_EQ((*suboption)->enterprise_identifier, vendor_suboption.enterprise_identifier);
        ASSERT_EQ((*suboption)->option, vendor_suboption.option);
        ASSERT_EQ(*(uint8_t*)(*suboption)->data, *(uint8_t*)vendor_suboption.data);
}

static void test_lease_managed(sd_dhcp6_client *client) {
        sd_dhcp6_lease *lease;
        struct in6_addr addr;
        usec_t lt_pref, lt_valid;
        uint8_t *id, prefixlen;
        size_t len;

        ASSERT_OK(sd_dhcp6_client_get_lease(client, &lease));

        ASSERT_OK(dhcp6_lease_get_serverid(lease, &id, &len));
        ASSERT_MEMEQ_NN(id, len, server_id, sizeof(server_id));

        ASSERT_TRUE(sd_dhcp6_lease_has_address(lease));
        ASSERT_TRUE(sd_dhcp6_lease_has_pd_prefix(lease));

        for (unsigned i = 0; i < 2; i++) {
                ASSERT_TRUE(sd_dhcp6_lease_address_iterator_reset(lease));
                ASSERT_OK(sd_dhcp6_lease_get_address(lease, &addr));
                ASSERT_OK(sd_dhcp6_lease_get_address_lifetime(lease, &lt_pref, &lt_valid));
                ASSERT_TRUE(in6_addr_equal(&addr, &ia_na_address1));
                ASSERT_EQ(lt_pref, 150 * USEC_PER_SEC);
                ASSERT_EQ(lt_valid, 180 * USEC_PER_SEC);
                ASSERT_TRUE(sd_dhcp6_lease_address_iterator_next(lease));
                ASSERT_OK(sd_dhcp6_lease_get_address(lease, &addr));
                ASSERT_OK(sd_dhcp6_lease_get_address_lifetime(lease, &lt_pref, &lt_valid));
                ASSERT_TRUE(in6_addr_equal(&addr, &ia_na_address2));
                ASSERT_EQ(lt_pref, 150 * USEC_PER_SEC);
                ASSERT_EQ(lt_valid, 180 * USEC_PER_SEC);
                ASSERT_FALSE(sd_dhcp6_lease_address_iterator_next(lease));

                ASSERT_TRUE(sd_dhcp6_lease_pd_iterator_reset(lease));
                ASSERT_OK(sd_dhcp6_lease_get_pd_prefix(lease, &addr, &prefixlen));
                ASSERT_OK(sd_dhcp6_lease_get_pd_lifetime(lease, &lt_pref, &lt_valid));
                ASSERT_TRUE(in6_addr_equal(&addr, &ia_pd_prefix1));
                ASSERT_EQ(prefixlen, 64);
                ASSERT_EQ(lt_pref, 150 * USEC_PER_SEC);
                ASSERT_EQ(lt_valid, 180 * USEC_PER_SEC);
                ASSERT_TRUE(sd_dhcp6_lease_pd_iterator_next(lease));
                ASSERT_OK(sd_dhcp6_lease_get_pd_prefix(lease, &addr, &prefixlen));
                ASSERT_OK(sd_dhcp6_lease_get_pd_lifetime(lease, &lt_pref, &lt_valid));
                ASSERT_TRUE(in6_addr_equal(&addr, &ia_pd_prefix2));
                ASSERT_EQ(prefixlen, 64);
                ASSERT_EQ(lt_pref, 150 * USEC_PER_SEC);
                ASSERT_EQ(lt_valid, 180 * USEC_PER_SEC);
                ASSERT_FALSE(sd_dhcp6_lease_pd_iterator_next(lease));
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

                ASSERT_TRUE(IN_SET(test_client_sent_message_count, 1, 2));

                test_lease_common(client);

                if (test_client_sent_message_count == 1) {
                        /* Starting the client again, e.g. on RA, is refused within the information refresh
                         * time, but the lease must be kept. */
                        ASSERT_OK(sd_dhcp6_client_start(client));
                        ASSERT_FALSE(sd_dhcp6_client_is_running(client));
                        test_lease_common(client);

                        /* In the information request mode, the information is requested again. */
                        ASSERT_OK(sd_dhcp6_client_send_renew(client));
                        ASSERT_OK(dhcp6_client_set_transaction_id(
                                        client, ((const DHCP6Message*) msg_reply)->transaction_id));
                        break;
                }

                ASSERT_OK(sd_dhcp6_client_set_information_request(client, /* enabled= */ false));
                ASSERT_OK(sd_dhcp6_client_start(client));
                ASSERT_OK(dhcp6_client_set_transaction_id(
                                client, ((const DHCP6Message*) msg_advertise)->transaction_id));
                break;

        case SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE:
                log_debug("/* %s (event=ip-acquire) */", __func__);

                ASSERT_TRUE(IN_SET(test_client_sent_message_count, 4, 6, 7));

                test_lease_managed(client);

                switch (test_client_sent_message_count) {
                case 4:
                        /* The FQDN can be changed while the client is running, and the new one is sent
                         * in the following messages. */
                        ASSERT_OK(sd_dhcp6_client_set_fqdn(client, "next.lab.intra"));

                        ASSERT_OK(sd_dhcp6_client_stop(client));
                        ASSERT_OK(sd_dhcp6_client_start(client));
                        ASSERT_OK(dhcp6_client_set_transaction_id(
                                        client, ((const DHCP6Message*) msg_reply)->transaction_id));
                        break;

                case 6:
                        /* Renew the lease on request, e.g. to send the new FQDN immediately. */
                        ASSERT_OK(sd_dhcp6_client_send_renew(client));
                        ASSERT_OK(dhcp6_client_set_transaction_id(
                                        client, ((const DHCP6Message*) msg_reply)->transaction_id));
                        break;

                case 7:
                        ASSERT_OK(sd_event_exit(sd_dhcp6_client_get_event(client), /* code= */ 0));
                        break;

                default:
                        assert_not_reached();
                }

                break;

        case DHCP6_CLIENT_EVENT_TEST_ADVERTISED: {
                sd_dhcp6_lease *lease;
                uint8_t preference;

                log_debug("/* %s (event=test-advertised) */", __func__);

                ASSERT_EQ(test_client_sent_message_count, 3u);

                test_lease_managed(client);

                ASSERT_OK(sd_dhcp6_client_get_lease(client, &lease));
                ASSERT_OK(dhcp6_lease_get_preference(lease, &preference));
                ASSERT_EQ(preference, 0xff);

                ASSERT_OK(dhcp6_client_set_transaction_id(
                                client, ((const DHCP6Message*) msg_reply)->transaction_id));
                break;
        }
        default:
                assert_not_reached();
        }
}

static int test_reconfigure_send(const void *packet, size_t len);

int dhcp6_network_send_udp_socket(int s, const struct in6_addr *a, const void *packet, size_t len) {
        if (test_reconfigure)
                return test_reconfigure_send(packet, len);

        log_debug("/* %s(count=%u) */", __func__, test_client_sent_message_count);

        ASSERT_NOT_NULL(a);
        ASSERT_TRUE(in6_addr_equal(a, &mcast_address));
        ASSERT_NOT_NULL(packet);
        ASSERT_GE(len, sizeof(DHCP6Message));

        switch (test_client_sent_message_count) {
        case 0:
        case 1:
                test_client_verify_information_request(packet, len);
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_reply, sizeof(msg_reply)),
                                   (ssize_t) sizeof(msg_reply));
                break;

        case 2:
                test_client_verify_solicit(packet, len);
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_advertise, sizeof(msg_advertise)),
                                   (ssize_t) sizeof(msg_advertise));
                break;

        case 3:
                test_client_callback(client_ref, DHCP6_CLIENT_EVENT_TEST_ADVERTISED, /* userdata= */ NULL);
                test_client_verify_request(packet, len);
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_reply, sizeof(msg_reply)),
                                   (ssize_t) sizeof(msg_reply));
                break;

        case 4:
                test_client_verify_release(packet, len);
                /* when stopping, dhcp6 client doesn't wait for release server reply */
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_reply, sizeof(msg_reply)),
                                   (ssize_t) sizeof(msg_reply));
                break;

        case 5:
                test_client_verify_solicit_with_new_fqdn(packet, len);
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_reply, sizeof(msg_reply)),
                                   (ssize_t) sizeof(msg_reply));
                break;

        case 6:
                test_client_verify_renew_with_new_fqdn(packet, len);
                ASSERT_OK_EQ_ERRNO(write(test_fd[1], msg_reply, sizeof(msg_reply)),
                                   (ssize_t) sizeof(msg_reply));
                break;

        default:
                assert_not_reached();
        }

        test_client_sent_message_count++;
        return len;
}

int dhcp6_network_bind_udp_socket(int ifindex, const struct in6_addr *a) {
        ASSERT_EQ(ifindex, test_ifindex);
        ASSERT_NOT_NULL(a);
        ASSERT_TRUE(in6_addr_equal(a, &local_address));

        /* The Reconfigure test queues several messages at once, which must not be merged. */
        ASSERT_OK_ERRNO(socketpair(AF_UNIX, (test_reconfigure ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                   0, test_fd));
        return TAKE_FD(test_fd[0]);
}

TEST(dhcp6_client) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_add_time_relative(e, /* ret= */ NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, /* accuracy= */ 0,
                                             /* callback= */ NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, e, /* priority= */ 0));
        ASSERT_OK_ZERO(sd_dhcp6_client_set_ifindex(client, test_ifindex));
        ASSERT_OK(sd_dhcp6_client_set_local_address(client, &local_address));
        ASSERT_OK(sd_dhcp6_client_set_fqdn(client, "host.lab.intra"));
        ASSERT_OK(sd_dhcp6_client_set_iaid(client, unaligned_read_be32((uint8_t[]) { IA_ID_BYTES })));
        ASSERT_OK(sd_dhcp6_client_set_send_release(client, /* enable= */ true));

        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER));
        ASSERT_OK(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVER));

        ASSERT_OK(sd_dhcp6_client_set_information_request(client, /* enabled= */ true));
        ASSERT_OK(sd_dhcp6_client_set_callback(client, test_client_callback, /* userdata= */ NULL));

        /* Nothing to renew when the client is not running. */
        ASSERT_OK_ZERO(sd_dhcp6_client_send_renew(client));

        ASSERT_OK(sd_dhcp6_client_start(client));

        ASSERT_OK(dhcp6_client_set_transaction_id(
                        client, ((const DHCP6Message*) msg_reply)->transaction_id));

        ASSERT_NOT_NULL(client_ref = sd_dhcp6_client_ref(client));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(test_client_sent_message_count, 7u);

        ASSERT_NULL(sd_dhcp6_client_unref(client_ref));
        test_fd[1] = safe_close(test_fd[1]);
}

static const uint8_t reconfigure_key[DHCP_RKAP_KEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};
static const uint8_t reconfigure_key_other[DHCP_RKAP_KEY_SIZE] = {
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
};

static bool test_message_has_option(const DHCP6Message *msg, size_t len, uint16_t code) {
        size_t options_len = len - offsetof(DHCP6Message, options);

        for (size_t offset = 0; offset < options_len;) {
                const uint8_t *optval;
                uint16_t optcode;
                size_t optlen;

                ASSERT_OK(dhcp6_option_parse(msg->options, options_len, &offset, &optcode, &optlen, &optval));
                if (optcode == code)
                        return true;
        }

        return false;
}

static void test_reconfigure_write_reply(const uint8_t *key, uint64_t replay) {
        uint8_t buf[sizeof(msg_reply) + offsetof(DHCP6Option, data) + sizeof(DHCPRKAPAuth)];
        size_t len = sizeof(msg_reply);

        memcpy(buf, msg_reply, sizeof(msg_reply));

        if (key) {
                DHCPRKAPAuth auth = {
                        .protocol = DHCP_RKAP_PROTOCOL,
                        .algorithm = DHCP_RKAP_ALGORITHM_HMAC_MD5,
                        .rdm = DHCP_RKAP_RDM_MONOTONIC,
                        .replay = htobe64(replay),
                        .type = DHCP_RKAP_TYPE_KEY,
                };

                memcpy(auth.value, key, sizeof(auth.value));
                unaligned_write_be16(buf + len, SD_DHCP6_OPTION_AUTH);
                unaligned_write_be16(buf + len + 2, sizeof(auth));
                memcpy(buf + len + offsetof(DHCP6Option, data), &auth, sizeof(auth));
                len += offsetof(DHCP6Option, data) + sizeof(auth);
        }

        ASSERT_OK(dhcp6_client_set_transaction_id(client_ref, ((const DHCP6Message*) msg_reply)->transaction_id));
        ASSERT_OK_EQ_ERRNO(write(test_fd[1], buf, len), (ssize_t) len);
}

typedef enum ReconfigureFlaw {
        RECONFIGURE_VALID,
        RECONFIGURE_BAD_DIGEST,
        RECONFIGURE_NO_AUTH,
        RECONFIGURE_OTHER_SERVER,
        RECONFIGURE_OTHER_CLIENT,
        RECONFIGURE_WRONG_PROTOCOL,
} ReconfigureFlaw;

static void test_reconfigure_write(uint8_t msg_type, uint64_t replay, ReconfigureFlaw flaw) {
        uint8_t sid[] = { SERVER_ID_BYTES }, cid[] = { CLIENT_ID_BYTES };
        uint8_t buf[256];
        size_t len = 0;

        log_debug("/* %s(%s, replay=%" PRIu64 ", flaw=%u) */", __func__,
                  dhcp6_message_type_to_string(msg_type), replay, flaw);

        if (flaw == RECONFIGURE_OTHER_SERVER)
                sid[sizeof(sid) - 1] ^= 0xff;
        if (flaw == RECONFIGURE_OTHER_CLIENT)
                cid[sizeof(cid) - 1] ^= 0xff;

        /* RFC 9915 section 18.3.11: the transaction ID is zero. */
        buf[len++] = DHCP6_MESSAGE_RECONFIGURE;
        buf[len++] = 0;
        buf[len++] = 0;
        buf[len++] = 0;

        unaligned_write_be16(buf + len, SD_DHCP6_OPTION_SERVERID);
        unaligned_write_be16(buf + len + 2, sizeof(sid));
        memcpy(buf + len + 4, sid, sizeof(sid));
        len += 4 + sizeof(sid);

        unaligned_write_be16(buf + len, SD_DHCP6_OPTION_CLIENTID);
        unaligned_write_be16(buf + len + 2, sizeof(cid));
        memcpy(buf + len + 4, cid, sizeof(cid));
        len += 4 + sizeof(cid);

        unaligned_write_be16(buf + len, SD_DHCP6_OPTION_RECONF_MSG);
        unaligned_write_be16(buf + len + 2, 1);
        buf[len + 4] = msg_type;
        len += 5;

        if (flaw != RECONFIGURE_NO_AUTH) {
                DHCPRKAPAuth auth = {
                        .protocol = flaw == RECONFIGURE_WRONG_PROTOCOL ? 2 : DHCP_RKAP_PROTOCOL,
                        .algorithm = DHCP_RKAP_ALGORITHM_HMAC_MD5,
                        .rdm = DHCP_RKAP_RDM_MONOTONIC,
                        .replay = htobe64(replay),
                        .type = DHCP_RKAP_TYPE_HMAC_MD5,
                };
                size_t auth_offset = len + 4;

                unaligned_write_be16(buf + len, SD_DHCP6_OPTION_AUTH);
                unaligned_write_be16(buf + len + 2, sizeof(auth));
                memcpy(buf + auth_offset, &auth, sizeof(auth));
                len += 4 + sizeof(auth);

                /* The digest is computed with the digest field zeroed (RFC 9915 section 20.4.2). */
                hmac_md5(reconfigure_key, sizeof(reconfigure_key), buf, len,
                         buf + auth_offset + offsetof(DHCPRKAPAuth, value));
                if (flaw == RECONFIGURE_BAD_DIGEST)
                        buf[auth_offset + offsetof(DHCPRKAPAuth, value)] ^= 0x01;
        }

        ASSERT_OK_EQ_ERRNO(write(test_fd[1], buf, len), (ssize_t) len);
}

static int test_reconfigure_stateless_send(const void *packet, size_t len) {
        const DHCP6Message *msg = packet;

        log_debug("/* %s(count=%u, type=%s) */", __func__, test_reconfigure_count,
                  dhcp6_message_type_to_string(msg->type));

        ASSERT_GE(len, sizeof(DHCP6Message));
        ASSERT_EQ(msg->type, DHCP6_MESSAGE_INFORMATION_REQUEST);
        ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));

        switch (test_reconfigure_count) {
        case 0:
                /* The initial Information-request. The server hands out the key in the Reply. */
                ASSERT_FALSE(test_message_has_option(msg, len, SD_DHCP6_OPTION_SERVERID));
                test_reconfigure_write_reply(reconfigure_key, /* replay= */ 10);
                break;

        case 1:
        case 2:
                /* Triggered by a Reconfigure message: RFC 9915 section 18.2.6 requires the Server
                 * Identifier. Only the valid Reconfigure message must have been accepted, see
                 * test_reconfigure_stateless_callback(). */
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_SERVERID));
                ASSERT_EQ(client_ref->reconfigure_key.replay, test_reconfigure_count == 1 ? 11u : 12u);
                test_reconfigure_write_reply(/* key= */ NULL, /* replay= */ 0);
                break;

        default:
                assert_not_reached();
        }

        test_reconfigure_count++;
        return len;
}

static int test_reconfigure_send(const void *packet, size_t len) {
        const DHCP6Message *msg = packet;

        if (test_reconfigure_stateless)
                return test_reconfigure_stateless_send(packet, len);

        log_debug("/* %s(count=%u, type=%s) */", __func__, test_reconfigure_count,
                  dhcp6_message_type_to_string(msg->type));

        ASSERT_GE(len, sizeof(DHCP6Message));

        switch (test_reconfigure_count) {
        case 0:
                /* The client announces that it accepts Reconfigure messages, and the server hands out the
                 * key in the (rapid commit) Reply. */
                ASSERT_EQ(msg->type, DHCP6_MESSAGE_SOLICIT);
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));
                test_reconfigure_write_reply(reconfigure_key, /* replay= */ 10);
                break;

        case 1:
                /* Triggered by the valid Reconfigure message. The Reply does not carry the key again. */
                ASSERT_EQ(msg->type, DHCP6_MESSAGE_RENEW);
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));
                test_reconfigure_write_reply(/* key= */ NULL, /* replay= */ 0);
                break;

        case 2:
                ASSERT_EQ(msg->type, DHCP6_MESSAGE_REBIND);
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));
                test_reconfigure_write_reply(/* key= */ NULL, /* replay= */ 0);
                break;

        case 3:
                /* Triggered by a Reconfigure message: the bindings are not included, but the Server
                 * Identifier is (RFC 9915 section 18.2.6). The Reply carries a new key with an old replay
                 * detection value, which must be ignored (RFC 9915 section 20.3). */
                ASSERT_EQ(msg->type, DHCP6_MESSAGE_INFORMATION_REQUEST);
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));
                ASSERT_TRUE(test_message_has_option(msg, len, SD_DHCP6_OPTION_SERVERID));
                ASSERT_FALSE(test_message_has_option(msg, len, SD_DHCP6_OPTION_IA_NA));
                ASSERT_FALSE(test_message_has_option(msg, len, SD_DHCP6_OPTION_IA_PD));
                test_reconfigure_write_reply(reconfigure_key_other, /* replay= */ 10);
                break;

        case 4:
                /* Release, when stopping the client. */
                ASSERT_EQ(msg->type, DHCP6_MESSAGE_RELEASE);
                ASSERT_FALSE(test_message_has_option(msg, len, SD_DHCP6_OPTION_RECONF_ACCEPT));
                break;

        default:
                assert_not_reached();
        }

        test_reconfigure_count++;
        return len;
}

static void test_reconfigure_callback(sd_dhcp6_client *client, int event, void *userdata) {
        if (event == SD_DHCP6_CLIENT_EVENT_STOP)
                return;

        ASSERT_EQ(event, SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE);
        ASSERT_TRUE(client->reconfigure_key.set);

        switch (test_reconfigure_count) {
        case 1:
                /* All but the last one must be ignored. They request Rebind, the valid one Renew, so that an
                 * accepted invalid message would make the client send Rebind next. */
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 11, RECONFIGURE_BAD_DIGEST);
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 11, RECONFIGURE_NO_AUTH);
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 11, RECONFIGURE_OTHER_SERVER);
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 11, RECONFIGURE_OTHER_CLIENT);
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 11, RECONFIGURE_WRONG_PROTOCOL);
                /* The replay detection value must be larger than the one of the key. */
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 10, RECONFIGURE_VALID);
                test_reconfigure_write(DHCP6_MESSAGE_RENEW, 11, RECONFIGURE_VALID);
                /* Received while renewing, hence ignored (RFC 9915 section 18.2.11). */
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 12, RECONFIGURE_VALID);
                break;

        case 2:
                /* The key is kept over the Renew. A replayed message is ignored. */
                test_reconfigure_write(DHCP6_MESSAGE_RENEW, 11, RECONFIGURE_VALID);
                test_reconfigure_write(DHCP6_MESSAGE_REBIND, 13, RECONFIGURE_VALID);
                break;

        case 3:
                /* A bound client can also be asked to request the other information again. */
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 14, RECONFIGURE_VALID);
                break;

        case 4:
                /* The bindings are kept, and so is the previous key. */
                ASSERT_EQ(client->state, DHCP6_STATE_BOUND);
                ASSERT_NOT_NULL(client->lease->ia_na);
                ASSERT_NOT_NULL(client->lease->ia_pd);
                ASSERT_EQ(memcmp(client->reconfigure_key.key, reconfigure_key, sizeof(reconfigure_key)), 0);
                ASSERT_EQ(client->reconfigure_key.replay, 14u);

                ASSERT_OK(sd_dhcp6_client_stop(client));
                ASSERT_FALSE(client->reconfigure_key.set);
                ASSERT_OK(sd_event_exit(sd_dhcp6_client_get_event(client), /* code= */ 0));
                break;

        default:
                assert_not_reached();
        }
}

static void test_reconfigure_stateless_callback(sd_dhcp6_client *client, int event, void *userdata) {
        if (event == SD_DHCP6_CLIENT_EVENT_STOP)
                return;

        ASSERT_EQ(event, SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST);
        ASSERT_TRUE(client->reconfigure_key.set);
        ASSERT_FALSE(sd_dhcp6_client_is_running(client));

        switch (test_reconfigure_count) {
        case 1:
                /* A stateless client can only send an Information-request. */
                test_reconfigure_write(DHCP6_MESSAGE_RENEW, 11, RECONFIGURE_VALID);
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 11, RECONFIGURE_BAD_DIGEST);
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 11, RECONFIGURE_OTHER_SERVER);
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 10, RECONFIGURE_VALID);
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 11, RECONFIGURE_VALID);
                break;

        case 2:
                /* The key is kept, a replayed message is ignored. */
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 11, RECONFIGURE_VALID);
                test_reconfigure_write(DHCP6_MESSAGE_INFORMATION_REQUEST, 12, RECONFIGURE_VALID);
                break;

        case 3:
                ASSERT_OK(sd_dhcp6_client_stop(client));
                ASSERT_FALSE(client->reconfigure_key.set);
                ASSERT_OK(sd_event_exit(sd_dhcp6_client_get_event(client), /* code= */ 0));
                break;

        default:
                assert_not_reached();
        }
}

TEST(dhcp6_client_reconfigure_stateless) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        test_reconfigure = true;
        test_reconfigure_stateless = true;
        test_reconfigure_count = 0;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_add_time_relative(e, /* ret= */ NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, /* accuracy= */ 0,
                                             /* callback= */ NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, e, /* priority= */ 0));
        ASSERT_OK_ZERO(sd_dhcp6_client_set_ifindex(client, test_ifindex));
        ASSERT_OK(sd_dhcp6_client_set_local_address(client, &local_address));
        ASSERT_OK(sd_dhcp6_client_set_information_request(client, /* enabled= */ true));
        ASSERT_OK(sd_dhcp6_client_set_accept_reconfigure(client, /* enable= */ true));
        ASSERT_OK(sd_dhcp6_client_set_callback(client, test_reconfigure_stateless_callback, /* userdata= */ NULL));

        ASSERT_NOT_NULL(client_ref = sd_dhcp6_client_ref(client));

        ASSERT_OK(sd_dhcp6_client_start(client));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(test_reconfigure_count, 3u);

        ASSERT_NULL(sd_dhcp6_client_unref(client_ref));
        test_fd[1] = safe_close(test_fd[1]);
        test_reconfigure = false;
        test_reconfigure_stateless = false;
}

TEST(dhcp6_client_reconfigure) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        test_reconfigure = true;
        test_reconfigure_count = 0;

        ASSERT_OK(sd_event_new(&e));
        ASSERT_OK(sd_event_add_time_relative(e, /* ret= */ NULL, CLOCK_BOOTTIME,
                                             30 * USEC_PER_SEC, /* accuracy= */ 0,
                                             /* callback= */ NULL, INT_TO_PTR(-ETIMEDOUT)));

        ASSERT_OK(sd_dhcp6_client_new(&client));
        ASSERT_OK(sd_dhcp6_client_attach_event(client, e, /* priority= */ 0));
        ASSERT_OK_ZERO(sd_dhcp6_client_set_ifindex(client, test_ifindex));
        ASSERT_OK(sd_dhcp6_client_set_local_address(client, &local_address));
        ASSERT_OK(sd_dhcp6_client_set_iaid(client, unaligned_read_be32((uint8_t[]) { IA_ID_BYTES })));
        ASSERT_OK(sd_dhcp6_client_set_send_release(client, /* enable= */ true));
        ASSERT_OK(sd_dhcp6_client_set_accept_reconfigure(client, /* enable= */ true));
        ASSERT_OK(sd_dhcp6_client_set_callback(client, test_reconfigure_callback, /* userdata= */ NULL));

        ASSERT_NOT_NULL(client_ref = sd_dhcp6_client_ref(client));

        ASSERT_OK(sd_dhcp6_client_start(client));

        ASSERT_OK(sd_event_loop(e));

        ASSERT_EQ(test_reconfigure_count, 5u);

        ASSERT_NULL(sd_dhcp6_client_unref(client_ref));
        test_fd[1] = safe_close(test_fd[1]);
        test_reconfigure = false;
}

static int intro(void) {
        ASSERT_OK_ERRNO(setenv("SYSTEMD_NETWORK_TEST_MODE", "1", 1));
        return 0;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
