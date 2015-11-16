/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen <teg@jklm.no>

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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/veth.h>
#include <net/if.h>

#include "sd-event.h"
#include "sd-ipv4acd.h"
#include "sd-netlink.h"

#include "event-util.h"
#include "in-addr-util.h"
#include "netlink-util.h"
#include "util.h"

static void acd_handler(sd_ipv4acd *acd, int event, void *userdata) {
        assert_se(acd);

        switch (event) {
        case SD_IPV4ACD_EVENT_BIND:
                log_info("bound");
                break;
        case SD_IPV4ACD_EVENT_CONFLICT:
                log_info("conflict");
                break;
        case SD_IPV4ACD_EVENT_STOP:
                log_error("the client was stopped");
                break;
        default:
                assert_not_reached("invalid ACD event");
        }
}

static int client_run(int ifindex, const struct in_addr *pa, const struct ether_addr *ha, sd_event *e) {
        sd_ipv4acd *acd;

        assert_se(sd_ipv4acd_new(&acd) >= 0);
        assert_se(sd_ipv4acd_attach_event(acd, e, 0) >= 0);

        assert_se(sd_ipv4acd_set_index(acd, ifindex) >= 0);
        assert_se(sd_ipv4acd_set_mac(acd, ha) >= 0);
        assert_se(sd_ipv4acd_set_address(acd, pa) >= 0);
        assert_se(sd_ipv4acd_set_callback(acd, acd_handler, NULL) >= 0);

        log_info("starting IPv4ACD client");

        assert_se(sd_ipv4acd_start(acd) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(!sd_ipv4acd_unref(acd));

        return EXIT_SUCCESS;
}

static int test_acd(const char *ifname, const char *address) {
        _cleanup_event_unref_ sd_event *e = NULL;
        _cleanup_netlink_unref_ sd_netlink *rtnl = NULL;
        _cleanup_netlink_message_unref_ sd_netlink_message *m = NULL, *reply = NULL;
        union in_addr_union pa;
        struct ether_addr ha;
        int ifindex;

        assert_se(in_addr_from_string(AF_INET, address, &pa) >= 0);

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_netlink_open(&rtnl) >= 0);
        assert_se(sd_netlink_attach_event(rtnl, e, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(m, IFLA_IFNAME, ifname) >= 0);
        assert_se(sd_netlink_call(rtnl, m, 0, &reply) >= 0);

        assert_se(sd_rtnl_message_link_get_ifindex(reply, &ifindex) >= 0);
        assert_se(sd_netlink_message_read_ether_addr(reply, IFLA_ADDRESS, &ha) >= 0);

        client_run(ifindex, &pa.in, &ha, e);

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        if (argc == 3)
                return test_acd(argv[1], argv[2]);
        else {
                log_error("This program takes two arguments.\n"
                          "\t %s <ifname> <IPv4 address>", program_invocation_short_name);
                return EXIT_FAILURE;
        }
}
