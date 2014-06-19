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

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *e;

        assert_se(sd_event_new(&e) >= 0);

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_client_basic(e);

        return 0;
}
