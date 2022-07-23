/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/veth.h>

#include "sd-event.h"
#include "sd-ipv4ll.h"
#include "sd-netlink.h"

#include "alloc-util.h"
#include "in-addr-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

static void ll_handler(sd_ipv4ll *ll, int event, void *userdata) {
        assert_se(ll);

        struct in_addr addr;
        const char *pretty = sd_ipv4ll_get_address(ll, &addr) >= 0 ? IN4_ADDR_TO_STRING(&addr) : NULL;

        switch (event) {
        case SD_IPV4LL_EVENT_BIND:
                log_info("bound %s", strna(pretty));
                break;
        case SD_IPV4LL_EVENT_CONFLICT:
                log_info("conflict on %s", strna(pretty));
                break;
        case SD_IPV4LL_EVENT_STOP:
                log_error("the client was stopped with address %s", strna(pretty));
                break;
        default:
                assert_not_reached();
        }
}

static int client_run(int ifindex, const char *seed_str, const struct in_addr *start_address, const struct ether_addr *ha, sd_event *e) {
        sd_ipv4ll *ll;

        assert_se(sd_ipv4ll_new(&ll) >= 0);
        assert_se(sd_ipv4ll_attach_event(ll, e, 0) >= 0);

        assert_se(sd_ipv4ll_set_ifindex(ll, ifindex) >= 0);
        assert_se(sd_ipv4ll_set_mac(ll, ha) >= 0);
        assert_se(sd_ipv4ll_set_callback(ll, ll_handler, NULL) >= 0);

        if (seed_str) {
                unsigned seed;

                assert_se(safe_atou(seed_str, &seed) >= 0);

                assert_se(sd_ipv4ll_set_address_seed(ll, seed) >= 0);
        }

        if (start_address && in4_addr_is_set(start_address))
                assert_se(sd_ipv4ll_set_address(ll, start_address) >= 0);

        log_info("starting IPv4LL client");

        assert_se(sd_ipv4ll_start(ll) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(!sd_ipv4ll_unref(ll));

        return EXIT_SUCCESS;
}

static int test_ll(const char *ifname, const char *seed, const struct in_addr *start_address) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL, *reply = NULL;
        struct ether_addr ha;
        int ifindex;

        assert_se(sd_event_new(&e) >= 0);

        assert_se(sd_netlink_open(&rtnl) >= 0);
        assert_se(sd_netlink_attach_event(rtnl, e, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(m, IFLA_IFNAME, ifname) >= 0);
        assert_se(sd_netlink_call(rtnl, m, 0, &reply) >= 0);

        assert_se(sd_rtnl_message_link_get_ifindex(reply, &ifindex) >= 0);
        assert_se(sd_netlink_message_read_ether_addr(reply, IFLA_ADDRESS, &ha) >= 0);

        client_run(ifindex, seed, start_address, &ha, e);

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        if (argc == 2)
                return test_ll(argv[1], NULL, NULL);
        else if (argc == 3) {
                int r;
                union in_addr_union a;

                r = in_addr_from_string(AF_INET, argv[2], &a);
                if (r < 0)
                        return test_ll(argv[1], argv[2], NULL);
                else
                        return test_ll(argv[1], NULL, &a.in);
        } else {
                log_error("This program takes one or two arguments.\n"
                          "\t %s <ifname> [<seed>|<start_address>]", program_invocation_short_name);
                return EXIT_FAILURE;
        }
}
