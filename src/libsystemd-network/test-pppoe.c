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
#include <linux/veth.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

#include "sd-event.h"
#include "sd-netlink.h"
#include "sd-pppoe.h"

#include "event-util.h"
#include "process-util.h"
#include "util.h"

static void pppoe_handler(sd_pppoe *ppp, int event, void *userdata) {
        static int pppoe_state = -1;
        sd_event *e = userdata;

        assert_se(ppp);
        assert_se(e);

        switch (event) {
        case SD_PPPOE_EVENT_RUNNING:
                assert_se(pppoe_state == -1);
                log_info("running");
                break;
        case SD_PPPOE_EVENT_STOPPED:
                assert_se(pppoe_state == SD_PPPOE_EVENT_RUNNING);
                log_info("stopped");
                assert_se(sd_event_exit(e, 0) >= 0);
                break;
        default:
                assert_not_reached("invalid pppoe event");
        }

        pppoe_state = event;
}

static int client_run(const char *client_name, sd_event *e) {
        sd_pppoe *pppoe;
        int client_ifindex;

        client_ifindex = (int) if_nametoindex(client_name);
        assert_se(client_ifindex > 0);

        assert_se(sd_pppoe_new(&pppoe) >= 0);
        assert_se(sd_pppoe_attach_event(pppoe, e, 0) >= 0);

        assert_se(sd_pppoe_set_ifname(pppoe, "pppoe-client") >= 0);
        assert_se(sd_pppoe_set_ifindex(pppoe, client_ifindex) >= 0);
        assert_se(sd_pppoe_set_callback(pppoe, pppoe_handler, e) >= 0);

        log_info("starting PPPoE client, it will exit when the server times out and sends PADT");

        assert_se(sd_pppoe_start(pppoe) >= 0);

        assert_se(sd_event_loop(e) >= 0);

        assert_se(!sd_pppoe_unref(pppoe));

        return EXIT_SUCCESS;
}

static int test_pppoe_server(sd_event *e) {
        sd_netlink *rtnl;
        sd_netlink_message *m;
        pid_t pid;
        int r, client_ifindex, server_ifindex;

        r = unshare(CLONE_NEWNET);
        if (r < 0 && errno == EPERM)
                return EXIT_TEST_SKIP;

        assert_se(r >= 0);

        assert_se(sd_netlink_open(&rtnl) >= 0);
        assert_se(sd_netlink_attach_event(rtnl, e, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0) >= 0);
        assert_se(sd_netlink_message_append_string(m, IFLA_IFNAME, "pppoe-server") >= 0);
        assert_se(sd_netlink_message_open_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "veth") >= 0);
        assert_se(sd_netlink_message_open_container(m, VETH_INFO_PEER) >= 0);
        assert_se(sd_netlink_message_append_string(m, IFLA_IFNAME, "pppoe-client") >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);
        assert_se(sd_netlink_call(rtnl, m, 0, NULL) >= 0);

        client_ifindex = (int) if_nametoindex("pppoe-client");
        assert_se(client_ifindex > 0);
        server_ifindex = (int) if_nametoindex("pppoe-server");
        assert_se(server_ifindex > 0);

        m = sd_netlink_message_unref(m);
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, client_ifindex) >= 0);
        assert_se(sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP) >= 0);
        assert_se(sd_netlink_call(rtnl, m, 0, NULL) >= 0);

        m = sd_netlink_message_unref(m);
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, server_ifindex) >= 0);
        assert_se(sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP) >= 0);
        assert_se(sd_netlink_call(rtnl, m, 0, NULL) >= 0);

        pid = fork();
        assert_se(pid >= 0);
        if (pid == 0) {
                /* let the client send some discover messages before the server is started */
                sleep(2);

                /* TODO: manage pppoe-server-options */
                execlp("pppoe-server", "pppoe-server", "-F",
                       "-I", "pppoe-server",
                       "-C", "Test-AC",
                       "-S", "Service-Default",
                       "-S", "Service-First-Auxiliary",
                       "-S", "Service-Second-Auxiliary",
                       NULL);
                assert_not_reached("failed to execute pppoe-server. not installed?");
        }

        client_run("pppoe-client", e);

        assert_se(kill(pid, SIGTERM) >= 0);
        assert_se(wait_for_terminate(pid, NULL) >= 0);

        assert_se(!sd_netlink_message_unref(m));
        assert_se(!sd_netlink_unref(rtnl));

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        _cleanup_event_unref_ sd_event *e = NULL;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        assert_se(sd_event_new(&e) >= 0);

        if (argc == 1) {
                log_info("running PPPoE client against local server");

                return test_pppoe_server(e);
        } else if (argc == 2) {
                log_info("running PPPoE client over '%s'", argv[1]);

                return client_run(argv[1], e);
        } else {
                log_error("This program takes one or no arguments.\n"
                          "\t %s [<ifname>]", program_invocation_short_name);
                return EXIT_FAILURE;
        }
}
