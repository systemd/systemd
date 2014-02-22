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

#include <netinet/ether.h>

#include "util.h"
#include "macro.h"
#include "sd-rtnl.h"
#include "socket-util.h"
#include "rtnl-util.h"
#include "event-util.h"
#include "missing.h"

static void test_link_configure(sd_rtnl *rtnl, int ifindex) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *message;
        uint16_t type;
        const char *mac = "98:fe:94:3f:c6:18", *name = "test";
        unsigned int mtu = 1450;
        void *data;

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_rtnl_message_append_string(message, IFLA_IFNAME, name) >= 0);
        assert_se(sd_rtnl_message_append_ether_addr(message, IFLA_ADDRESS, ether_aton(mac)) >= 0);
        assert_se(sd_rtnl_message_append_u32(message, IFLA_MTU, mtu) >= 0);

        assert_se(sd_rtnl_call(rtnl, message, 0, NULL) == 1);

        assert_se(sd_rtnl_message_read(message, &type, &data) > 0);
        assert_se(type == IFLA_IFNAME);
        assert_se(streq(name, (char *) data));

        assert_se(sd_rtnl_message_read(message, &type, &data) > 0);
        assert_se(type == IFLA_ADDRESS);
        assert_se(streq(mac, ether_ntoa(data)));

        assert_se(sd_rtnl_message_read(message, &type, &data) > 0);
        assert_se(type == IFLA_MTU);
        assert_se(mtu == *(unsigned int *) data);
}

static void test_link_get(sd_rtnl *rtnl, int ifindex) {
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        unsigned int mtu = 1500;
        unsigned int *mtu_reply;
        void *data;
        uint16_t type;

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);
        assert_se(m);

        /* u8 test cases  */
        assert_se(sd_rtnl_message_append_u8(m, IFLA_CARRIER, 0) >= 0);
        assert_se(sd_rtnl_message_append_u8(m, IFLA_OPERSTATE, 0) >= 0);
        assert_se(sd_rtnl_message_append_u8(m, IFLA_LINKMODE, 0) >= 0);

        /* u32 test cases */
        assert_se(sd_rtnl_message_append_u32(m, IFLA_MTU, mtu) >= 0);
        assert_se(sd_rtnl_message_append_u32(m, IFLA_GROUP, 0) >= 0);
        assert_se(sd_rtnl_message_append_u32(m, IFLA_TXQLEN, 0) >= 0);
        assert_se(sd_rtnl_message_append_u32(m, IFLA_NUM_TX_QUEUES, 0) >= 0);
        assert_se(sd_rtnl_message_append_u32(m, IFLA_NUM_RX_QUEUES, 0) >= 0);

        assert_se(sd_rtnl_call(rtnl, m, -1, &r) == 1);

        /* u8 read back */
        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_CARRIER);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_OPERSTATE);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_LINKMODE);

        /* u32 read back */
        assert_se(sd_rtnl_message_read(m, &type, (void **) &mtu_reply) == 1);
        assert_se(type == IFLA_MTU);
        assert_se(*mtu_reply == mtu);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_GROUP);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_TXQLEN);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_NUM_TX_QUEUES);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 1);
        assert_se(type == IFLA_NUM_RX_QUEUES);

        while (sd_rtnl_message_read(r, &type, &data) > 0) {
                switch (type) {
//                        case IFLA_MTU:
//                                assert_se(*(unsigned int *) data == 65536);
//                                break;
//                        case IFLA_QDISC:
//                                assert_se(streq((char *) data, "noqueue"));
//                                break;
                        case IFLA_IFNAME:
                                assert_se(streq((char *) data, "lo"));
                                break;
                }
        }

        assert_se(sd_rtnl_flush(rtnl) >= 0);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);

}

static void test_route(void) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req;
        struct in_addr addr;
        uint32_t index = 2;
        uint16_t type;
        void *data;
        int r;

        r = sd_rtnl_message_new_route(NULL, &req, RTM_NEWROUTE, AF_INET);
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

        assert_se(rtnl_message_seal(NULL, req) >= 0);

        assert_se(sd_rtnl_message_read(req, &type, &data) > 0);
        assert_se(type == RTA_GATEWAY);
        assert_se(((struct in_addr *)data)->s_addr == addr.s_addr);

        assert_se(sd_rtnl_message_read(req, &type, &data) > 0);
        assert_se(type == RTA_OIF);
        assert_se(*(uint32_t *) data == index);
}

static void test_multiple(void) {
        sd_rtnl *rtnl1, *rtnl2;

        assert_se(sd_rtnl_open(&rtnl1, 0) >= 0);
        assert_se(sd_rtnl_open(&rtnl2, 0) >= 0);

        rtnl1 = sd_rtnl_unref(rtnl1);
        rtnl2 = sd_rtnl_unref(rtnl2);
}

static int link_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        void *data;
        uint16_t type;
        char *ifname = userdata;

        assert_se(rtnl);
        assert_se(m);

        log_info("got link info about %s", ifname);
        free(ifname);

        while (sd_rtnl_message_read(m, &type, &data) > 0) {
                switch (type) {
//                        case IFLA_MTU:
//                                assert_se(*(unsigned int *) data == 65536);
//                                break;
//                        case IFLA_QDISC:
//                                assert_se(streq((char *) data, "noqueue"));
//                                break;
                        case IFLA_IFNAME:
                                assert_se(streq((char *) data, "lo"));
                                break;
                }
        }

        return 1;
}

static void test_event_loop(int ifindex) {
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        char *ifname;

        ifname = strdup("lo2");
        assert_se(ifname);

        assert_se(sd_rtnl_open(&rtnl, 0) >= 0);
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);

        assert_se(sd_rtnl_call_async(rtnl, m, &link_handler, ifname, 0, NULL) >= 0);

        assert_se(sd_event_default(&event) >= 0);

        assert_se(sd_rtnl_attach_event(rtnl, event, 0) >= 0);

        assert_se(sd_event_run(event, 0) >= 0);

        assert_se(sd_rtnl_detach_event(rtnl) >= 0);
}

static int pipe_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        int *counter = userdata;

        (*counter) --;

        log_info("got reply, %d left in pipe", *counter);

        return sd_rtnl_message_get_errno(m);
}

static void test_async(int ifindex) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL, *r = NULL;
        uint32_t serial;
        char *ifname;

        ifname = strdup("lo");
        assert_se(ifname);

        assert_se(sd_rtnl_open(&rtnl, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, ifindex) >= 0);

        assert_se(sd_rtnl_call_async(rtnl, m, &link_handler, ifname, 0, &serial) >= 0);

        assert_se(sd_rtnl_wait(rtnl, 0) >= 0);
        assert_se(sd_rtnl_process(rtnl, &r) >= 0);
}

static void test_pipe(int ifindex) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m1 = NULL, *m2 = NULL;
        int counter = 0;

        assert_se(sd_rtnl_open(&rtnl, 0) >= 0);

        assert_se(sd_rtnl_message_new_link(rtnl, &m1, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_rtnl_message_new_link(rtnl, &m2, RTM_GETLINK, ifindex) >= 0);

        counter ++;
        assert_se(sd_rtnl_call_async(rtnl, m1, &pipe_handler, &counter, 0, NULL) >= 0);

        counter ++;
        assert_se(sd_rtnl_call_async(rtnl, m2, &pipe_handler, &counter, 0, NULL) >= 0);

        while (counter > 0) {
                assert_se(sd_rtnl_wait(rtnl, 0) >= 0);
                assert_se(sd_rtnl_process(rtnl, NULL) >= 0);
        }
}

static void test_container(void) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        uint16_t type;
        void *data;

        assert_se(sd_rtnl_message_new_link(NULL, &m, RTM_NEWLINK, 0) >= 0);

        assert_se(sd_rtnl_message_open_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_rtnl_message_open_container(m, IFLA_LINKINFO) == -ENOTSUP);
        assert_se(sd_rtnl_message_append_string(m, IFLA_INFO_KIND, "kind") >= 0);
        assert_se(sd_rtnl_message_open_container(m, IFLA_INFO_DATA) >= 0);
        assert_se(sd_rtnl_message_open_container(m, IFLA_INFO_DATA) == -ENOTSUP);
        assert_se(sd_rtnl_message_append_u16(m, IFLA_VLAN_ID, 100) >= 0);
        assert_se(sd_rtnl_message_close_container(m) >= 0);
        assert_se(sd_rtnl_message_append_string(m, IFLA_INFO_KIND, "kind") >= 0);
        assert_se(sd_rtnl_message_close_container(m) >= 0);
        assert_se(sd_rtnl_message_close_container(m) == -EINVAL);

        assert_se(rtnl_message_seal(NULL, m) >= 0);

        assert_se(sd_rtnl_message_read(m, &type, &data) >= 0);
        assert_se(type == IFLA_LINKINFO);
        assert_se(data == NULL);
        assert_se(sd_rtnl_message_read(m, &type, &data) >= 0);
        assert_se(type == IFLA_INFO_KIND);
        assert_se(streq("kind", (char *)data));
        assert_se(sd_rtnl_message_read(m, &type, &data) >= 0);
        assert_se(type == IFLA_INFO_DATA);
        assert_se(data == NULL);
        assert_se(sd_rtnl_message_read(m, &type, &data) >= 0);
        assert_se(type == IFLA_VLAN_ID);
        assert_se(*(uint16_t *)data == 100);
        assert_se(sd_rtnl_message_read(m, &type, &data) == 0);
        assert_se(sd_rtnl_message_exit_container(m) >= 0);
        assert_se(sd_rtnl_message_read(m, &type, &data) >= 0);
        assert_se(type == IFLA_INFO_KIND);
        assert_se(streq("kind", (char *)data));
        assert_se(sd_rtnl_message_read(m, &type, &data) == 0);
        assert_se(sd_rtnl_message_exit_container(m) >= 0);
        assert_se(sd_rtnl_message_exit_container(m) == -EINVAL);
}

static void test_match(void) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;

        assert_se(sd_rtnl_open(&rtnl, 0) >= 0);

        assert_se(sd_rtnl_add_match(rtnl, RTM_NEWLINK, &link_handler, NULL) >= 0);
        assert_se(sd_rtnl_add_match(rtnl, RTM_NEWLINK, &link_handler, NULL) >= 0);

        assert_se(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 1);
        assert_se(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 1);
        assert_se(sd_rtnl_remove_match(rtnl, RTM_NEWLINK, &link_handler, NULL) == 0);
}

int main(void) {
        sd_rtnl *rtnl;
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        void *data;
        int if_loopback;
        uint16_t type;

        test_match();

        test_multiple();

        test_route();

        test_container();

        assert_se(sd_rtnl_open(&rtnl, 0) >= 0);
        assert_se(rtnl);

        if_loopback = (int) if_nametoindex("lo");
        assert_se(if_loopback > 0);

        test_async(if_loopback);

        test_pipe(if_loopback);

        test_event_loop(if_loopback);

        test_link_configure(rtnl, if_loopback);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, if_loopback) >= 0);
        assert_se(m);

        assert_se(sd_rtnl_message_get_type(m, &type) >= 0);
        assert_se(type == RTM_GETLINK);

        assert_se(sd_rtnl_message_read(m, &type, &data) == -EPERM);

        assert_se(sd_rtnl_call(rtnl, m, 0, &r) == 1);
        assert_se(sd_rtnl_message_get_type(r, &type) >= 0);
        assert_se(type == RTM_NEWLINK);

        assert_se(sd_rtnl_message_read(m, &type, &data) == 0);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);

        assert_se(sd_rtnl_call(rtnl, m, -1, &r) == -EPERM);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);

        test_link_get(rtnl, if_loopback);

        assert_se(sd_rtnl_flush(rtnl) >= 0);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);
        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);

        return EXIT_SUCCESS;
}
