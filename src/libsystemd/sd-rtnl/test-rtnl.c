/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <linux/rtnetlink.h>
#include <netinet/ether.h>

#include "util.h"
#include "macro.h"
#include "sd-rtnl.h"
#include "socket-util.h"
#include "rtnl-util.h"
#include "event-util.h"

static void test_link_configure(sd_rtnl *rtnl, int ifindex) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *message;
        uint16_t type;
        const char *mac = "98:fe:94:3f:c6:18", *name = "test";
        unsigned int mtu = 1450;
        void *data;

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, &message) >= 0);
        assert(sd_rtnl_message_append_string(message, IFLA_IFNAME, name) >= 0);
        assert(sd_rtnl_message_append_ether_addr(message, IFLA_ADDRESS, ether_aton(mac)) >= 0);
        assert(sd_rtnl_message_append_u32(message, IFLA_MTU, mtu) >= 0);

        assert(sd_rtnl_message_read(message, &type, &data) > 0);
        assert(type == IFLA_IFNAME);
        assert(streq(name, (char *) data));

        assert(sd_rtnl_message_read(message, &type, &data) > 0);
        assert(type == IFLA_ADDRESS);
        assert(streq(mac, ether_ntoa(data)));

        assert(sd_rtnl_message_read(message, &type, &data) > 0);
        assert(type == IFLA_MTU);
        assert(mtu == *(unsigned int *) data);

        assert(sd_rtnl_call(rtnl, message, 0, NULL) == 1);
}

static void test_route(void) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req;
        struct in_addr addr;
        uint32_t index = 2;
        uint16_t type;
        void *data;
        int r;

        r = sd_rtnl_message_route_new(RTM_NEWROUTE, AF_INET, &req);
        if (r < 0) {
                log_error("Could not create RTM_NEWROUTE message: %s", strerror(-r));
                return;
        }

        addr.s_addr = htonl(INADDR_LOOPBACK);

        r = sd_rtnl_message_append_in_addr(req, RTA_GATEWAY, &addr);
        if (r < 0) {
                log_error("Could not append RTA_GATEWAY attribute: %s", strerror(-r));
                return;
        }

        r = sd_rtnl_message_append_u32(req, RTA_OIF, index);
        if (r < 0) {
                log_error("Could not append RTA_OIF attribute: %s", strerror(-r));
                return;
        }

        assert(sd_rtnl_message_read(req, &type, &data) > 0);
        assert(type == RTA_GATEWAY);
        assert(((struct in_addr *)data)->s_addr == addr.s_addr);

        assert(sd_rtnl_message_read(req, &type, &data) > 0);
        assert(type == RTA_OIF);
        assert(*(uint32_t *) data == index);
}

static void test_multiple(void) {
        sd_rtnl *rtnl1, *rtnl2;

        assert(sd_rtnl_open(0, &rtnl1) >= 0);
        assert(sd_rtnl_open(0, &rtnl2) >= 0);

        rtnl1 = sd_rtnl_unref(rtnl1);
        rtnl2 = sd_rtnl_unref(rtnl2);
}

static int link_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        void *data;
        uint16_t type;
        char *ifname = userdata;

        assert(rtnl);
        assert(m);

        log_info("got link info about %s", ifname);
        free(ifname);

        while (sd_rtnl_message_read(m, &type, &data) > 0) {
                switch (type) {
//                        case IFLA_MTU:
//                                assert(*(unsigned int *) data == 65536);
//                                break;
//                        case IFLA_QDISC:
//                                assert(streq((char *) data, "noqueue"));
//                                break;
                        case IFLA_IFNAME:
                                assert(streq((char *) data, "lo"));
                                break;
                }
        }

        return 1;
}

static void test_event_loop(int ifindex) {
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        char *ifname;

        ifname = strdup("lo2");
        assert(ifname);

        assert(sd_rtnl_open(0, &rtnl) >= 0);
        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, &m) >= 0);

        assert(sd_rtnl_call_async(rtnl, m, &link_handler, ifname, 0, NULL) >= 0);

        assert(sd_event_default(&event) >= 0);

        assert(sd_rtnl_attach_event(rtnl, event, 0) >= 0);

        assert(sd_event_run(event, 0) >= 0);

        assert(sd_rtnl_detach_event(rtnl) >= 0);
}

static int pipe_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        int *counter = userdata;

        (*counter) --;

        log_info("got reply, %d left in pipe", *counter);

        return sd_rtnl_message_get_errno(m);
}

static void test_async(int ifindex) {
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *m = NULL, *r = NULL;
        uint32_t serial;
        char *ifname;

        ifname = strdup("lo");
        assert(ifname);

        assert(sd_rtnl_open(0, &rtnl) >= 0);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, &m) >= 0);

        assert(sd_rtnl_call_async(rtnl, m, &link_handler, ifname, 0, &serial) >= 0);

        assert(sd_rtnl_wait(rtnl, 0) >= 0);
        assert(sd_rtnl_process(rtnl, &r) >= 0);
}

static void test_pipe(int ifindex) {
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *m1 = NULL, *m2 = NULL;
        int counter = 0;

        assert(sd_rtnl_open(0, &rtnl) >= 0);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, &m1) >= 0);
        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, &m2) >= 0);

        counter ++;
        assert(sd_rtnl_call_async(rtnl, m1, &pipe_handler, &counter, 0, NULL) >= 0);

        counter ++;
        assert(sd_rtnl_call_async(rtnl, m2, &pipe_handler, &counter, 0, NULL) >= 0);

        while (counter > 0) {
                assert(sd_rtnl_wait(rtnl, 0) >= 0);
                assert(sd_rtnl_process(rtnl, NULL) >= 0);
        }
}

static void test_container(void) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        uint16_t type;
        void *data;

        assert(sd_rtnl_message_link_new(RTM_NEWLINK, 0, &m) >= 0);

        assert(sd_rtnl_message_open_container(m, IFLA_LINKINFO) >= 0);
        assert(sd_rtnl_message_open_container(m, IFLA_LINKINFO) == -EINVAL);
        assert(sd_rtnl_message_append_string(m, IFLA_INFO_KIND, "kind") >= 0);
        assert(sd_rtnl_message_close_container(m) >= 0);
        assert(sd_rtnl_message_close_container(m) == -EINVAL);

        assert(sd_rtnl_message_read(m, &type, &data) == -EINVAL);

/* TODO: add support for entering containers
        assert(sd_rtnl_message_read(m, &type, &data) > 0);
        assert(type == IFLA_INFO_KIND);
        assert(streq("kind", (char *) data));

        assert(sd_rtnl_message_read(m, &type, &data) == 0);
*/
}

static void test_match(void) {
        _cleanup_sd_rtnl_unref_ sd_rtnl *rtnl = NULL;

        assert(sd_rtnl_open(0, &rtnl) >= 0);

        assert(sd_rtnl_add_match(rtnl, RTM_NEWLINK, &link_handler, NULL) >= 0);
        assert(sd_rtnl_add_match(rtnl, RTM_NEWLINK, &link_handler, NULL) >= 0);

        assert(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 1);
        assert(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 1);
        assert(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 0);
}

int main(void) {
        sd_rtnl *rtnl;
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        void *data;
        int if_loopback;
        uint16_t type;
        unsigned int mtu = 0;
        unsigned int *mtu_reply;

        test_match();

        test_multiple();

        test_route();

        test_container();

        assert(sd_rtnl_open(0, &rtnl) >= 0);
        assert(rtnl);

        if_loopback = (int) if_nametoindex("lo");
        assert(if_loopback > 0);

        test_async(if_loopback);

        test_pipe(if_loopback);

        test_event_loop(if_loopback);

        test_link_configure(rtnl, if_loopback);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, if_loopback, &m) >= 0);
        assert(m);

        assert(sd_rtnl_message_get_type(m, &type) >= 0);
        assert(type == RTM_GETLINK);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);

        assert(sd_rtnl_call(rtnl, m, 0, &r) == 1);
        assert(sd_rtnl_message_get_type(r, &type) >= 0);
        assert(type == RTM_NEWLINK);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);
        assert((r = sd_rtnl_message_unref(r)) == NULL);

        assert(sd_rtnl_call(rtnl, m, -1, &r) == -EPERM);
        assert((m = sd_rtnl_message_unref(m)) == NULL);
        assert((r = sd_rtnl_message_unref(r)) == NULL);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, if_loopback, &m) >= 0);
        assert(m);

        assert(sd_rtnl_message_append_u32(m, IFLA_MTU, mtu) >= 0);
        assert(sd_rtnl_message_read(m, &type, (void **) &mtu_reply) == 1);

        assert(type == IFLA_MTU);
        assert(*mtu_reply == 0);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);

        assert(sd_rtnl_call(rtnl, m, -1, &r) == 1);
        while (sd_rtnl_message_read(r, &type, &data) > 0) {
                switch (type) {
//                        case IFLA_MTU:
//                                assert(*(unsigned int *) data == 65536);
//                                break;
//                        case IFLA_QDISC:
//                                assert(streq((char *) data, "noqueue"));
//                                break;
                        case IFLA_IFNAME:
                                assert(streq((char *) data, "lo"));
                                break;
                }
        }

        assert(sd_rtnl_flush(rtnl) >= 0);

        assert((m = sd_rtnl_message_unref(m)) == NULL);
        assert((r = sd_rtnl_message_unref(r)) == NULL);
        assert((rtnl = sd_rtnl_unref(rtnl)) == NULL);

        return EXIT_SUCCESS;
}
