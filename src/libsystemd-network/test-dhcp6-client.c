/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-event.h"

#include "dhcp-duid-internal.h"
#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "macro.h"
#include "memory-util.h"
#include "socket-util.h"
#include "string-util.h"
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
#define CLIENT_ID_BYTES                                                 \
        0x00, 0x02, 0x00, 0x00, 0xab, 0x11, 0x61, 0x77, 0x40, 0xde, 0x13, 0x42, 0xc3, 0xa2
#define SERVER_ID_BYTES                                                 \
        0x00, 0x01, 0x00, 0x01, 0x19, 0x40, 0x5c, 0x53, 0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53
#define VENDOR_SUBOPTION_BYTES                                         \
        0x01

static const struct in6_addr local_address =
        { { { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, } } };
static const struct in6_addr mcast_address =
        IN6ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS_INIT;
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
        assert_se(dhcp6_option_parse_domainname(data, 5, &domain) >= 0);
        assert_se(domain);
        assert_se(streq(domain, "test"));
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
        /* Domain list */
        0x00, SD_DHCP6_OPTION_DOMAIN, 0x00, 0x0b,
        0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x12,
        0x01, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a',
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
        /* Domain list */
        0x00, SD_DHCP6_OPTION_DOMAIN, 0x00, 0x0b,
        0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a', 0x00,
        /* Client FQDN */
        0x00, SD_DHCP6_OPTION_CLIENT_FQDN, 0x00, 0x12,
        0x01, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x03, 'l', 'a', 'b', 0x05, 'i', 'n', 't', 'r', 'a',
        /* Vendor specific options */
        0x00, SD_DHCP6_OPTION_VENDOR_OPTS, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x20, 0x00, 0xf7, 0x00, 0x01, VENDOR_SUBOPTION_BYTES,
};

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

int dhcp6_network_send_udp_socket(int s, struct in6_addr *a, const void *packet, size_t len) {
        log_debug("/* %s(count=%u) */", __func__, test_client_sent_message_count);

        assert_se(a);
        assert_se(in6_addr_equal(a, &mcast_address));
        assert_se(packet);
        assert_se(len >= sizeof(DHCP6Message));

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

int dhcp6_network_bind_udp_socket(int ifindex, struct in6_addr *a) {
        assert_se(ifindex == test_ifindex);
        assert_se(a);
        assert_se(in6_addr_equal(a, &local_address));

        assert_se(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_fd) >= 0);
        return TAKE_FD(test_fd[0]);
}

TEST(dhcp6_client) {
        _cleanup_(sd_dhcp6_client_unrefp) sd_dhcp6_client *client = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_event_add_time_relative(e, NULL, CLOCK_BOOTTIME,
                                             2 * USEC_PER_SEC, 0,
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
