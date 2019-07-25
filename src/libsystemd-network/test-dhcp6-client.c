/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2014 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-dhcp6-client.h"
#include "sd-event.h"

#include "dhcp6-internal.h"
#include "dhcp6-lease-internal.h"
#include "dhcp6-protocol.h"
#include "fd-util.h"
#include "macro.h"
#include "memory-util.h"
#include "socket-util.h"
#include "tests.h"
#include "time-util.h"
#include "virt.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static sd_event_source *hangcheck;
static int test_dhcp_fd[2];
static int test_index = 42;
static int test_client_message_num;
static be32_t test_iaid = 0;
static uint8_t test_duid[14] = { };

static int test_client_basic(sd_event *e) {
        sd_dhcp6_client *client;
        int v;

        log_debug("/* %s */", __func__);

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(client);

        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);

        assert_se(sd_dhcp6_client_set_ifindex(client, 15) == 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, -42) == -EINVAL);
        assert_se(sd_dhcp6_client_set_ifindex(client, -1) == 0);
        assert_se(sd_dhcp6_client_set_ifindex(client, 42) >= 0);

        assert_se(sd_dhcp6_client_set_mac(client, (const uint8_t *) &mac_addr,
                                          sizeof (mac_addr),
                                          ARPHRD_ETHER) >= 0);

        assert_se(sd_dhcp6_client_set_fqdn(client, "host") == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, "host.domain") == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, NULL) == 1);
        assert_se(sd_dhcp6_client_set_fqdn(client, "~host") == -EINVAL);
        assert_se(sd_dhcp6_client_set_fqdn(client, "~host.domain") == -EINVAL);

        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_CLIENTID) == -EINVAL);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVERS) == -EEXIST);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_NTP_SERVER) == -EEXIST);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_SNTP_SERVERS) == -EEXIST);
        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DOMAIN_LIST) == -EEXIST);
        assert_se(sd_dhcp6_client_set_request_option(client, 10) == -EINVAL);

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
        assert_se(!sd_dhcp6_client_unref(client));

        return 0;
}

static int test_option(sd_event *e) {
        uint8_t packet[] = {
                'F', 'O', 'O',
                0x00, SD_DHCP6_OPTION_ORO, 0x00, 0x07,
                'A', 'B', 'C', 'D', 'E', 'F', 'G',
                0x00, SD_DHCP6_OPTION_VENDOR_CLASS, 0x00, 0x09,
                '1', '2', '3', '4', '5', '6', '7', '8', '9',
                'B', 'A', 'R',
        };
        uint8_t result[] = {
                'F', 'O', 'O',
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                'B', 'A', 'R',
        };
        uint16_t optcode;
        size_t optlen;
        uint8_t *optval, *buf, *out;
        size_t zero = 0, pos = 3;
        size_t buflen = sizeof(packet), outlen = sizeof(result);

        log_debug("/* %s */", __func__);

        assert_se(buflen == outlen);

        assert_se(dhcp6_option_parse(&buf, &zero, &optcode, &optlen,
                                     &optval) == -ENOMSG);

        buflen -= 3;
        buf = &packet[3];
        outlen -= 3;
        out = &result[3];

        assert_se(dhcp6_option_parse(&buf, &buflen, &optcode, &optlen,
                                     &optval) >= 0);
        pos += 4 + optlen;
        assert_se(buf == &packet[pos]);
        assert_se(optcode == SD_DHCP6_OPTION_ORO);
        assert_se(optlen == 7);
        assert_se(buflen + pos == sizeof(packet));

        assert_se(dhcp6_option_append(&out, &outlen, optcode, optlen,
                                      optval) >= 0);
        assert_se(out == &result[pos]);
        assert_se(*out == 0x00);

        assert_se(dhcp6_option_parse(&buf, &buflen, &optcode, &optlen,
                                     &optval) >= 0);
        pos += 4 + optlen;
        assert_se(buf == &packet[pos]);
        assert_se(optcode == SD_DHCP6_OPTION_VENDOR_CLASS);
        assert_se(optlen == 9);
        assert_se(buflen + pos == sizeof(packet));

        assert_se(dhcp6_option_append(&out, &outlen, optcode, optlen,
                                      optval) >= 0);
        assert_se(out == &result[pos]);
        assert_se(*out == 'B');

        assert_se(memcmp(packet, result, sizeof(packet)) == 0);

        return 0;
}

static int test_option_status(sd_event *e) {
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
                /* status option */
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
                /* status option */
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
                /* status option */
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
                /* status option */
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x00,
                /* IA PD Prefix #2 */
                0x00, 0x1a, 0x00, 0x1f,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x80, 0x20, 0x01, 0x0d, 0xb8, 0xc0, 0x0l, 0xd0,
                0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
                0x00, 0x0d, 0x00, 0x02, 0x00, 0x00,
        };
        DHCP6Option *option;
        DHCP6IA ia, pd;
        int r = 0;

        log_debug("/* %s */", __func__);

        zero(ia);
        option = (DHCP6Option *)option1;
        assert_se(sizeof(option1) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(option, &ia);
        assert_se(r == -EINVAL);
        assert_se(ia.addresses == NULL);

        option->len = htobe16(17);
        r = dhcp6_option_parse_ia(option, &ia);
        assert_se(r == -ENOBUFS);
        assert_se(ia.addresses == NULL);

        option->len = htobe16(sizeof(DHCP6Option));
        r = dhcp6_option_parse_ia(option, &ia);
        assert_se(r == -ENOBUFS);
        assert_se(ia.addresses == NULL);

        zero(ia);
        option = (DHCP6Option *)option2;
        assert_se(sizeof(option2) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(option, &ia);
        assert_se(r >= 0);
        assert_se(ia.addresses == NULL);

        zero(ia);
        option = (DHCP6Option *)option3;
        assert_se(sizeof(option3) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(option, &ia);
        assert_se(r >= 0);
        assert_se(ia.addresses != NULL);
        dhcp6_lease_free_ia(&ia);

        zero(pd);
        option = (DHCP6Option *)option4;
        assert_se(sizeof(option4) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(option, &pd);
        assert_se(r == 0);
        assert_se(pd.addresses != NULL);
        assert_se(memcmp(&pd.ia_pd.id, &option4[4], 4) == 0);
        assert_se(memcmp(&pd.ia_pd.lifetime_t1, &option4[8], 4) == 0);
        assert_se(memcmp(&pd.ia_pd.lifetime_t2, &option4[12], 4) == 0);
        dhcp6_lease_free_ia(&pd);

        zero(pd);
        option = (DHCP6Option *)option5;
        assert_se(sizeof(option5) == sizeof(DHCP6Option) + be16toh(option->len));

        r = dhcp6_option_parse_ia(option, &pd);
        assert_se(r == 0);
        assert_se(pd.addresses != NULL);
        dhcp6_lease_free_ia(&pd);

        return 0;
}

static uint8_t msg_advertise[198] = {
        0x02, 0x0f, 0xb4, 0xe5, 0x00, 0x01, 0x00, 0x0e,
        0x00, 0x01, 0x00, 0x01, 0x1a, 0x6b, 0xf3, 0x30,
        0x3c, 0x97, 0x0e, 0xcf, 0xa3, 0x7d, 0x00, 0x03,
        0x00, 0x5e, 0x0e, 0xcf, 0xa3, 0x7d, 0x00, 0x00,
        0x00, 0x50, 0x00, 0x00, 0x00, 0x78, 0x00, 0x05,
        0x00, 0x18, 0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad,
        0xbe, 0xef, 0x78, 0xee, 0x1c, 0xf3, 0x09, 0x3c,
        0x55, 0xad, 0x00, 0x00, 0x00, 0x96, 0x00, 0x00,
        0x00, 0xb4, 0x00, 0x0d, 0x00, 0x32, 0x00, 0x00,
        0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x28,
        0x65, 0x73, 0x29, 0x20, 0x72, 0x65, 0x6e, 0x65,
        0x77, 0x65, 0x64, 0x2e, 0x20, 0x47, 0x72, 0x65,
        0x65, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x20, 0x66,
        0x72, 0x6f, 0x6d, 0x20, 0x70, 0x6c, 0x61, 0x6e,
        0x65, 0x74, 0x20, 0x45, 0x61, 0x72, 0x74, 0x68,
        0x00, 0x17, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8,
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x0b,
        0x03, 0x6c, 0x61, 0x62, 0x05, 0x69, 0x6e, 0x74,
        0x72, 0x61, 0x00, 0x00, 0x1f, 0x00, 0x10, 0x20,
        0x01, 0x0d, 0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x19,
        0x40, 0x5c, 0x53, 0x78, 0x2b, 0xcb, 0xb3, 0x6d,
        0x53, 0x00, 0x07, 0x00, 0x01, 0x00
};

static uint8_t msg_reply[173] = {
        0x07, 0xf7, 0x4e, 0x57, 0x00, 0x02, 0x00, 0x0e,
        0x00, 0x01, 0x00, 0x01, 0x19, 0x40, 0x5c, 0x53,
        0x78, 0x2b, 0xcb, 0xb3, 0x6d, 0x53, 0x00, 0x01,
        0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1a, 0x6b,
        0xf3, 0x30, 0x3c, 0x97, 0x0e, 0xcf, 0xa3, 0x7d,
        0x00, 0x03, 0x00, 0x4a, 0x0e, 0xcf, 0xa3, 0x7d,
        0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x78,
        0x00, 0x05, 0x00, 0x18, 0x20, 0x01, 0x0d, 0xb8,
        0xde, 0xad, 0xbe, 0xef, 0x78, 0xee, 0x1c, 0xf3,
        0x09, 0x3c, 0x55, 0xad, 0x00, 0x00, 0x00, 0x96,
        0x00, 0x00, 0x00, 0xb4, 0x00, 0x0d, 0x00, 0x1e,
        0x00, 0x00, 0x41, 0x6c, 0x6c, 0x20, 0x61, 0x64,
        0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x20,
        0x77, 0x65, 0x72, 0x65, 0x20, 0x61, 0x73, 0x73,
        0x69, 0x67, 0x6e, 0x65, 0x64, 0x2e, 0x00, 0x17,
        0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad,
        0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x18, 0x00, 0x0b, 0x03, 0x6c,
        0x61, 0x62, 0x05, 0x69, 0x6e, 0x74, 0x72, 0x61,
        0x00, 0x00, 0x1f, 0x00, 0x10, 0x20, 0x01, 0x0d,
        0xb8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01
};

static uint8_t fqdn_wire[16] = {
        0x04, 'h', 'o', 's', 't', 0x03, 'l', 'a', 'b',
        0x05, 'i', 'n', 't', 'r', 'a', 0x00
};

static int test_advertise_option(sd_event *e) {
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        DHCP6Message *advertise = (DHCP6Message *)msg_advertise;
        size_t len = sizeof(msg_advertise) - sizeof(DHCP6Message), pos = 0;
        be32_t val;
        uint8_t preference = 255;
        struct in6_addr addr;
        uint32_t lt_pref, lt_valid;
        int r;
        uint8_t *opt;
        bool opt_clientid = false;
        struct in6_addr *addrs;
        char **domains;

        log_debug("/* %s */", __func__);

        assert_se(len >= sizeof(DHCP6Message));

        assert_se(dhcp6_lease_new(&lease) >= 0);

        assert_se(advertise->type == DHCP6_ADVERTISE);
        assert_se((be32toh(advertise->transaction_id) & 0x00ffffff) ==
                  0x0fb4e5);

        while (pos < len) {
                DHCP6Option *option = (DHCP6Option *)&advertise->options[pos];
                const uint16_t optcode = be16toh(option->code);
                const uint16_t optlen = be16toh(option->len);
                uint8_t *optval = option->data;

                switch(optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        assert_se(optlen == 14);

                        opt_clientid = true;
                        break;

                case SD_DHCP6_OPTION_IA_NA:
                        assert_se(optlen == 94);
                        assert_se(!memcmp(optval, &msg_advertise[26], optlen));

                        val = htobe32(0x0ecfa37d);
                        assert_se(!memcmp(optval, &val, sizeof(val)));

                        val = htobe32(80);
                        assert_se(!memcmp(optval + 4, &val, sizeof(val)));

                        val = htobe32(120);
                        assert_se(!memcmp(optval + 8, &val, sizeof(val)));

                        assert_se(dhcp6_option_parse_ia(option, &lease->ia) >= 0);

                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        assert_se(optlen == 14);
                        assert_se(!memcmp(optval, &msg_advertise[179], optlen));

                        assert_se(dhcp6_lease_set_serverid(lease, optval,
                                                           optlen) >= 0);
                        break;

                case SD_DHCP6_OPTION_PREFERENCE:
                        assert_se(optlen == 1);
                        assert_se(!*optval);

                        assert_se(dhcp6_lease_set_preference(lease,
                                                             *optval) >= 0);
                        break;

                case SD_DHCP6_OPTION_ELAPSED_TIME:
                        assert_se(optlen == 2);

                        break;

                case SD_DHCP6_OPTION_DNS_SERVERS:
                        assert_se(optlen == 16);
                        assert_se(dhcp6_lease_set_dns(lease, optval,
                                                      optlen) >= 0);
                        break;

                case SD_DHCP6_OPTION_DOMAIN_LIST:
                        assert_se(optlen == 11);
                        assert_se(dhcp6_lease_set_domains(lease, optval,
                                                          optlen) >= 0);
                        break;

                case SD_DHCP6_OPTION_SNTP_SERVERS:
                        assert_se(optlen == 16);
                        assert_se(dhcp6_lease_set_sntp(lease, optval,
                                                       optlen) >= 0);
                        break;

                default:
                        break;
                }

                pos += sizeof(*option) + optlen;
        }

        assert_se(pos == len);
        assert_se(opt_clientid);

        sd_dhcp6_lease_reset_address_iter(lease);
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) >= 0);
        assert_se(!memcmp(&addr, &msg_advertise[42], sizeof(addr)));
        assert_se(lt_pref == 150);
        assert_se(lt_valid == 180);
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) == -ENOMSG);

        sd_dhcp6_lease_reset_address_iter(lease);
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) >= 0);
        assert_se(!memcmp(&addr, &msg_advertise[42], sizeof(addr)));
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) == -ENOMSG);
        sd_dhcp6_lease_reset_address_iter(lease);
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) >= 0);
        assert_se(!memcmp(&addr, &msg_advertise[42], sizeof(addr)));
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) == -ENOMSG);

        assert_se(dhcp6_lease_get_serverid(lease, &opt, &len) >= 0);
        assert_se(len == 14);
        assert_se(!memcmp(opt, &msg_advertise[179], len));

        assert_se(dhcp6_lease_get_preference(lease, &preference) >= 0);
        assert_se(preference == 0);

        r = sd_dhcp6_lease_get_dns(lease, &addrs);
        assert_se(r == 1);
        assert_se(!memcmp(addrs, &msg_advertise[124], r * 16));

        r = sd_dhcp6_lease_get_domains(lease, &domains);
        assert_se(r == 1);
        assert_se(!strcmp("lab.intra", domains[0]));
        assert_se(domains[1] == NULL);

        r = sd_dhcp6_lease_get_ntp_addrs(lease, &addrs);
        assert_se(r == 1);
        assert_se(!memcmp(addrs, &msg_advertise[159], r * 16));

        return 0;
}

static int test_hangcheck(sd_event_source *s, uint64_t usec, void *userdata) {
        assert_not_reached("Test case should have completed in 2 seconds");

        return 0;
}

static void test_client_solicit_cb(sd_dhcp6_client *client, int event,
                                   void *userdata) {
        sd_event *e = userdata;
        sd_dhcp6_lease *lease;
        struct in6_addr *addrs;
        char **domains;

        log_debug("/* %s */", __func__);

        assert_se(e);
        assert_se(event == SD_DHCP6_CLIENT_EVENT_IP_ACQUIRE);

        assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);

        assert_se(sd_dhcp6_lease_get_domains(lease, &domains) == 1);
        assert_se(!strcmp("lab.intra", domains[0]));
        assert_se(domains[1] == NULL);

        assert_se(sd_dhcp6_lease_get_dns(lease, &addrs) == 1);
        assert_se(!memcmp(addrs, &msg_advertise[124], 16));

        assert_se(sd_dhcp6_lease_get_ntp_addrs(lease, &addrs) == 1);
        assert_se(!memcmp(addrs, &msg_advertise[159], 16));

        assert_se(sd_dhcp6_client_set_request_option(client, SD_DHCP6_OPTION_DNS_SERVERS) == -EBUSY);

        sd_event_exit(e, 0);
}

static int test_client_send_reply(DHCP6Message *request) {
        DHCP6Message reply;

        reply.transaction_id = request->transaction_id;
        reply.type = DHCP6_REPLY;

        memcpy(msg_reply, &reply.transaction_id, 4);

        memcpy(&msg_reply[26], test_duid, sizeof(test_duid));

        memcpy(&msg_reply[44], &test_iaid, sizeof(test_iaid));

        assert_se(write(test_dhcp_fd[1], msg_reply, sizeof(msg_reply))
                  == sizeof(msg_reply));

        return 0;
}

static int test_client_verify_request(DHCP6Message *request, size_t len) {
        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        size_t pos = 0;
        bool found_clientid = false, found_iana = false, found_serverid = false,
                found_elapsed_time = false, found_fqdn = false;
        struct in6_addr addr;
        be32_t val;
        uint32_t lt_pref, lt_valid;

        log_debug("/* %s */", __func__);

        assert_se(request->type == DHCP6_REQUEST);
        assert_se(dhcp6_lease_new(&lease) >= 0);

        len -= sizeof(DHCP6Message);

        while (pos < len) {
                DHCP6Option *option = (DHCP6Option *)&request->options[pos];
                uint16_t optcode = be16toh(option->code);
                uint16_t optlen = be16toh(option->len);
                uint8_t *optval = option->data;

                switch(optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        assert_se(!found_clientid);
                        found_clientid = true;

                        assert_se(!memcmp(optval, &test_duid,
                                          sizeof(test_duid)));

                        break;

                case SD_DHCP6_OPTION_IA_NA:
                        assert_se(!found_iana);
                        found_iana = true;

                        assert_se(optlen == 40);
                        assert_se(!memcmp(optval, &test_iaid, sizeof(test_iaid)));

                        val = htobe32(80);
                        assert_se(!memcmp(optval + 4, &val, sizeof(val)));

                        val = htobe32(120);
                        assert_se(!memcmp(optval + 8, &val, sizeof(val)));

                        assert_se(!dhcp6_option_parse_ia(option, &lease->ia));

                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        assert_se(!found_serverid);
                        found_serverid = true;

                        assert_se(optlen == 14);
                        assert_se(!memcmp(&msg_advertise[179], optval, optlen));

                        break;

                case SD_DHCP6_OPTION_ELAPSED_TIME:
                        assert_se(!found_elapsed_time);
                        found_elapsed_time = true;

                        assert_se(optlen == 2);

                        break;
                case SD_DHCP6_OPTION_FQDN:
                        assert_se(!found_fqdn);
                        found_fqdn = true;

                        assert_se(optlen == 17);

                        assert_se(optval[0] == 0x01);
                        assert_se(!memcmp(optval + 1, fqdn_wire, sizeof(fqdn_wire)));
                        break;
                }

                pos += sizeof(*option) + optlen;
        }

        assert_se(found_clientid && found_iana && found_serverid &&
                  found_elapsed_time);

        sd_dhcp6_lease_reset_address_iter(lease);
        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) >= 0);
        assert_se(!memcmp(&addr, &msg_advertise[42], sizeof(addr)));
        assert_se(lt_pref == 150);
        assert_se(lt_valid == 180);

        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) == -ENOMSG);

        return 0;
}

static int test_client_send_advertise(DHCP6Message *solicit) {
        DHCP6Message advertise;

        advertise.transaction_id = solicit->transaction_id;
        advertise.type = DHCP6_ADVERTISE;

        memcpy(msg_advertise, &advertise.transaction_id, 4);

        memcpy(&msg_advertise[8], test_duid, sizeof(test_duid));

        memcpy(&msg_advertise[26], &test_iaid, sizeof(test_iaid));

        assert_se(write(test_dhcp_fd[1], msg_advertise, sizeof(msg_advertise))
                  == sizeof(msg_advertise));

        return 0;
}

static int test_client_verify_solicit(DHCP6Message *solicit, size_t len) {
        bool found_clientid = false, found_iana = false,
                found_elapsed_time = false, found_fqdn = false;
        size_t pos = 0;

        log_debug("/* %s */", __func__);

        assert_se(solicit->type == DHCP6_SOLICIT);

        len -= sizeof(DHCP6Message);

        while (pos < len) {
                DHCP6Option *option = (DHCP6Option *)&solicit->options[pos];
                uint16_t optcode = be16toh(option->code);
                uint16_t optlen = be16toh(option->len);
                uint8_t *optval = option->data;

                switch(optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        assert_se(!found_clientid);
                        found_clientid = true;

                        assert_se(optlen == sizeof(test_duid));
                        memcpy(&test_duid, optval, sizeof(test_duid));

                        break;

                case SD_DHCP6_OPTION_IA_NA:
                        assert_se(!found_iana);
                        found_iana = true;

                        assert_se(optlen == 12);

                        memcpy(&test_iaid, optval, sizeof(test_iaid));

                        break;

                case SD_DHCP6_OPTION_ELAPSED_TIME:
                        assert_se(!found_elapsed_time);
                        found_elapsed_time = true;

                        assert_se(optlen == 2);

                        break;

                case SD_DHCP6_OPTION_FQDN:
                        assert_se(!found_fqdn);
                        found_fqdn = true;

                        assert_se(optlen == 17);

                        assert_se(optval[0] == 0x01);
                        assert_se(!memcmp(optval + 1, fqdn_wire, sizeof(fqdn_wire)));

                        break;
                }

                pos += sizeof(*option) + optlen;
        }

        assert_se(pos == len);
        assert_se(found_clientid && found_iana && found_elapsed_time);

        return 0;
}

static void test_client_information_cb(sd_dhcp6_client *client, int event,
                                       void *userdata) {
        sd_event *e = userdata;
        sd_dhcp6_lease *lease;
        struct in6_addr *addrs;
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };
        char **domains;

        log_debug("/* %s */", __func__);

        assert_se(e);
        assert_se(event == SD_DHCP6_CLIENT_EVENT_INFORMATION_REQUEST);

        assert_se(sd_dhcp6_client_get_lease(client, &lease) >= 0);

        assert_se(sd_dhcp6_lease_get_domains(lease, &domains) == 1);
        assert_se(!strcmp("lab.intra", domains[0]));
        assert_se(domains[1] == NULL);

        assert_se(sd_dhcp6_lease_get_dns(lease, &addrs) == 1);
        assert_se(!memcmp(addrs, &msg_advertise[124], 16));

        assert_se(sd_dhcp6_lease_get_ntp_addrs(lease, &addrs) == 1);
        assert_se(!memcmp(addrs, &msg_advertise[159], 16));

        assert_se(sd_dhcp6_client_set_information_request(client, false) == -EBUSY);
        assert_se(sd_dhcp6_client_set_callback(client, NULL, e) >= 0);
        assert_se(sd_dhcp6_client_stop(client) >= 0);
        assert_se(sd_dhcp6_client_set_information_request(client, false) >= 0);

        assert_se(sd_dhcp6_client_set_callback(client,
                                               test_client_solicit_cb, e) >= 0);

        assert_se(sd_dhcp6_client_set_local_address(client, &address) >= 0);

        assert_se(sd_dhcp6_client_start(client) >= 0);

}

static int test_client_verify_information_request(DHCP6Message *information_request,
                                                  size_t len) {

        _cleanup_(sd_dhcp6_lease_unrefp) sd_dhcp6_lease *lease = NULL;
        size_t pos = 0;
        bool found_clientid = false, found_elapsed_time = false;
        struct in6_addr addr;
        uint32_t lt_pref, lt_valid;

        log_debug("/* %s */", __func__);

        assert_se(information_request->type == DHCP6_INFORMATION_REQUEST);
        assert_se(dhcp6_lease_new(&lease) >= 0);

        len -= sizeof(DHCP6Message);

        while (pos < len) {
                DHCP6Option *option = (DHCP6Option *)&information_request->options[pos];
                uint16_t optcode = be16toh(option->code);
                uint16_t optlen = be16toh(option->len);
                uint8_t *optval = option->data;

                switch(optcode) {
                case SD_DHCP6_OPTION_CLIENTID:
                        assert_se(!found_clientid);
                        found_clientid = true;

                        assert_se(optlen == sizeof(test_duid));
                        memcpy(&test_duid, optval, sizeof(test_duid));

                        break;

                case SD_DHCP6_OPTION_IA_NA:
                        assert_not_reached("IA TA option must not be present");

                        break;

                case SD_DHCP6_OPTION_SERVERID:
                        assert_not_reached("Server ID option must not be present");

                        break;

                case SD_DHCP6_OPTION_ELAPSED_TIME:
                        assert_se(!found_elapsed_time);
                        found_elapsed_time = true;

                        assert_se(optlen == 2);

                        break;
                }

                pos += sizeof(*option) + optlen;
        }

        assert_se(pos == len);
        assert_se(found_clientid && found_elapsed_time);

        sd_dhcp6_lease_reset_address_iter(lease);

        assert_se(sd_dhcp6_lease_get_address(lease, &addr, &lt_pref,
                                             &lt_valid) == -ENOMSG);

        return 0;
}

int dhcp6_network_send_udp_socket(int s, struct in6_addr *server_address,
                                  const void *packet, size_t len) {
        struct in6_addr mcast =
                IN6ADDR_ALL_DHCP6_RELAY_AGENTS_AND_SERVERS_INIT;
        DHCP6Message *message;

        assert_se(s == test_dhcp_fd[0]);
        assert_se(server_address);
        assert_se(packet);
        assert_se(len > sizeof(DHCP6Message) + 4);
        assert_se(IN6_ARE_ADDR_EQUAL(server_address, &mcast));

        message = (DHCP6Message *)packet;

        assert_se(message->transaction_id & 0x00ffffff);

        if (test_client_message_num == 0) {
                test_client_verify_information_request(message, len);
                test_client_send_reply(message);
                test_client_message_num++;
        } else if (test_client_message_num == 1) {
                test_client_verify_solicit(message, len);
                test_client_send_advertise(message);
                test_client_message_num++;
        } else if (test_client_message_num == 2) {
                test_client_verify_request(message, len);
                test_client_send_reply(message);
                test_client_message_num++;
        }

        return len;
}

int dhcp6_network_bind_udp_socket(int index, struct in6_addr *local_address) {
        assert_se(index == test_index);

        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, test_dhcp_fd) < 0)
                return -errno;

        return test_dhcp_fd[0];
}

static int test_client_solicit(sd_event *e) {
        sd_dhcp6_client *client;
        usec_t time_now = now(clock_boottime_or_monotonic());
        struct in6_addr address = { { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } };
        int val;

        log_debug("/* %s */", __func__);

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(client);

        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);

        assert_se(sd_dhcp6_client_set_ifindex(client, test_index) == 0);
        assert_se(sd_dhcp6_client_set_mac(client, (const uint8_t *) &mac_addr,
                                          sizeof (mac_addr),
                                          ARPHRD_ETHER) >= 0);
        assert_se(sd_dhcp6_client_set_fqdn(client, "host.lab.intra") == 1);

        assert_se(sd_dhcp6_client_get_information_request(client, &val) >= 0);
        assert_se(val == 0);
        assert_se(sd_dhcp6_client_set_information_request(client, 42) >= 0);
        assert_se(sd_dhcp6_client_get_information_request(client, &val) >= 0);
        assert_se(val);

        assert_se(sd_dhcp6_client_set_callback(client,
                                               test_client_information_cb, e) >= 0);

        assert_se(sd_event_add_time(e, &hangcheck, clock_boottime_or_monotonic(),
                                    time_now + 2 * USEC_PER_SEC, 0,
                                    test_hangcheck, NULL) >= 0);

        assert_se(sd_dhcp6_client_set_local_address(client, &address) >= 0);

        assert_se(sd_dhcp6_client_start(client) >= 0);

        sd_event_loop(e);

        hangcheck = sd_event_source_unref(hangcheck);

        assert_se(!sd_dhcp6_client_unref(client));

        test_dhcp_fd[1] = safe_close(test_dhcp_fd[1]);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_event_unrefp) sd_event *e;

        assert_se(sd_event_new(&e) >= 0);

        test_setup_logging(LOG_DEBUG);

        test_client_basic(e);
        test_option(e);
        test_option_status(e);
        test_advertise_option(e);
        test_client_solicit(e);

        return 0;
}
