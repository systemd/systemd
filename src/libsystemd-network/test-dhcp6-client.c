/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>
#include <stdio.h>

#include "macro.h"
#include "sd-event.h"
#include "event-util.h"

#include "sd-dhcp6-client.h"
#include "dhcp6-protocol.h"
#include "dhcp6-internal.h"

static struct ether_addr mac_addr = {
        .ether_addr_octet = {'A', 'B', 'C', '1', '2', '3'}
};

static bool verbose = false;

static int test_client_basic(sd_event *e) {
        sd_dhcp6_client *client;

        if (verbose)
                printf("* %s\n", __FUNCTION__);

        assert_se(sd_dhcp6_client_new(&client) >= 0);
        assert_se(client);

        assert_se(sd_dhcp6_client_attach_event(client, e, 0) >= 0);

        assert_se(sd_dhcp6_client_set_index(client, 15) == 0);
        assert_se(sd_dhcp6_client_set_index(client, -42) == -EINVAL);
        assert_se(sd_dhcp6_client_set_index(client, -1) == 0);
        assert_se(sd_dhcp6_client_set_index(client, 42) >= 0);

        assert_se(sd_dhcp6_client_set_mac(client, &mac_addr) >= 0);

        assert_se(sd_dhcp6_client_set_callback(client, NULL, NULL) >= 0);

        assert_se(sd_dhcp6_client_detach_event(client) >= 0);
        assert_se(!sd_dhcp6_client_unref(client));

        return 0;
}

static int test_option(sd_event *e) {
        uint8_t packet[] = {
                'F', 'O', 'O',
                0x00, DHCP6_OPTION_ORO, 0x00, 0x07,
                'A', 'B', 'C', 'D', 'E', 'F', 'G',
                0x00, DHCP6_OPTION_VENDOR_CLASS, 0x00, 0x09,
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

        if (verbose)
                printf("* %s\n", __FUNCTION__);

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
        assert_se(optcode == DHCP6_OPTION_ORO);
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
        assert_se(optcode == DHCP6_OPTION_VENDOR_CLASS);
        assert_se(optlen == 9);
        assert_se(buflen + pos == sizeof(packet));

        assert_se(dhcp6_option_append(&out, &outlen, optcode, optlen,
                                      optval) >= 0);
        assert_se(out == &result[pos]);
        assert_se(*out == 'B');

        assert_se(memcmp(packet, result, sizeof(packet)) == 0);

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *e;

        assert_se(sd_event_new(&e) >= 0);

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_client_basic(e);
        test_option(e);

        assert_se(!sd_event_unref(e));

        return 0;
}
