/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/veth.h>
#include <net/if.h>

#include "sd-event.h"
#include "sd-ipv4acd.h"
#include "sd-netlink.h"

#include "in-addr-util.h"
#include "tests.h"
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
                assert_not_reached();
        }
}

static int client_run(int ifindex, const struct in_addr *pa, const struct ether_addr *ha, sd_event *e) {
        sd_ipv4acd *acd;

        assert_se(sd_ipv4acd_new(&acd) >= 0);
        assert_se(sd_ipv4acd_attach_event(acd, e, 0) >= 0);

        assert_se(sd_ipv4acd_set_ifindex(acd, ifindex) >= 0);
        assert_se(sd_ipv4acd_set_mac(acd, ha) >= 0);
        assert_se(sd_ipv4acd_set_address(acd, pa) >= 0);
        assert_se(sd_ipv4acd_set_callback(acd, acd_handler, NULL) >= 0);

        log_info("starting IPv4ACD client");

        assert_se(sd_ipv4acd_start(acd, true) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(!sd_ipv4acd_unref(acd));

        return EXIT_SUCCESS;
}

static int test_acd(const char *ifname, const char *address) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
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
        test_setup_logging(LOG_DEBUG);

        if (argc == 3)
                return test_acd(argv[1], argv[2]);
        else {
                log_error("This program takes two arguments.\n"
                          "\t %s <ifname> <IPv4 address>", program_invocation_short_name);
                return EXIT_FAILURE;
        }
}
