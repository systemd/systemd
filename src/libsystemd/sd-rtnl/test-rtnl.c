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
#include <net/if.h>

#include "util.h"
#include "macro.h"
#include "sd-rtnl.h"
#include "socket-util.h"
#include "rtnl-util.h"
#include "event-util.h"
#include "missing.h"
#include "rtnl-internal.h"

static void test_link_configure(sd_rtnl *rtnl, int ifindex) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *message;
        const char *mac = "98:fe:94:3f:c6:18", *name = "test";
        unsigned int mtu = 1450, mtu_out;
        char *name_out;
        struct ether_addr mac_out;

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        assert_se(sd_rtnl_message_new_link(rtnl, &message, RTM_GETLINK, ifindex) >= 0);
        assert_se(sd_rtnl_message_append_string(message, IFLA_IFNAME, name) >= 0);
        assert_se(sd_rtnl_message_append_ether_addr(message, IFLA_ADDRESS, ether_aton(mac)) >= 0);
        assert_se(sd_rtnl_message_append_u32(message, IFLA_MTU, mtu) >= 0);

        assert_se(sd_rtnl_call(rtnl, message, 0, NULL) == 1);
        assert_se(sd_rtnl_message_rewind(message) >= 0);

        assert_se(sd_rtnl_message_read_string(message, IFLA_IFNAME, &name_out) >= 0);
        assert_se(streq(name, name_out));

        assert_se(sd_rtnl_message_read_ether_addr(message, IFLA_ADDRESS, &mac_out) >= 0);
        assert_se(streq(mac, ether_ntoa(&mac_out)));

        assert_se(sd_rtnl_message_read_u32(message, IFLA_MTU, &mtu_out) >= 0);
        assert_se(mtu == mtu_out);
}

static void test_link_get(sd_rtnl *rtnl, int ifindex) {
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        unsigned int mtu = 1500;
        char *str_data;
        uint8_t u8_data;
        uint32_t u32_data;
        struct ether_addr eth_data;

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

        assert_se(sd_rtnl_message_read_string(r, IFLA_IFNAME, &str_data) == 0);

        assert_se(sd_rtnl_message_read_u8(r, IFLA_CARRIER, &u8_data) == 0);
        assert_se(sd_rtnl_message_read_u8(r, IFLA_OPERSTATE, &u8_data) == 0);
        assert_se(sd_rtnl_message_read_u8(r, IFLA_LINKMODE, &u8_data) == 0);

        assert_se(sd_rtnl_message_read_u32(r, IFLA_MTU, &u32_data) == 0);
        assert_se(sd_rtnl_message_read_u32(r, IFLA_GROUP, &u32_data) == 0);
        assert_se(sd_rtnl_message_read_u32(r, IFLA_TXQLEN, &u32_data) == 0);
        assert_se(sd_rtnl_message_read_u32(r, IFLA_NUM_TX_QUEUES, &u32_data) == 0);
        assert_se(sd_rtnl_message_read_u32(r, IFLA_NUM_RX_QUEUES, &u32_data) == 0);

        assert_se(sd_rtnl_message_read_ether_addr(r, IFLA_ADDRESS, &eth_data) == 0);

        assert_se(sd_rtnl_flush(rtnl) >= 0);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);
}


static void test_address_get(sd_rtnl *rtnl, int ifindex) {
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        struct in_addr in_data;
        struct ifa_cacheinfo cache;
        char *label;

        assert_se(sd_rtnl_message_new_addr(rtnl, &m, RTM_GETADDR, ifindex, AF_INET) >= 0);
        assert_se(m);

        assert_se(sd_rtnl_call(rtnl, m, -1, &r) == 1);

        assert_se(sd_rtnl_message_read_in_addr(r, IFA_LOCAL, &in_data) == 0);
        assert_se(sd_rtnl_message_read_in_addr(r, IFA_ADDRESS, &in_data) == 0);
        assert_se(sd_rtnl_message_read_string(r, IFA_LABEL, &label) == 0);
        assert_se(sd_rtnl_message_read_cache_info(r, IFA_CACHEINFO, &cache) == 0);

        assert_se(sd_rtnl_flush(rtnl) >= 0);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);

}

static void test_route(void) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req;
        struct in_addr addr, addr_data;
        uint32_t index = 2, u32_data;
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

        assert_se(sd_rtnl_message_rewind(req) >= 0);

        assert_se(sd_rtnl_message_read_in_addr(req, RTA_GATEWAY, &addr_data) >= 0);
        assert_se(addr_data.s_addr == addr.s_addr);

        assert_se(sd_rtnl_message_read_u32(req, RTA_OIF, &u32_data) >= 0);
        assert_se(u32_data == index);

        assert_se((req = sd_rtnl_message_unref(req)) == NULL);
}

static void test_multiple(void) {
        sd_rtnl *rtnl1, *rtnl2;

        assert_se(sd_rtnl_open(&rtnl1, 0) >= 0);
        assert_se(sd_rtnl_open(&rtnl2, 0) >= 0);

        rtnl1 = sd_rtnl_unref(rtnl1);
        rtnl2 = sd_rtnl_unref(rtnl2);
}

static int link_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        char *ifname = userdata, *data;

        assert_se(rtnl);
        assert_se(m);

        log_info("got link info about %s", ifname);
        free(ifname);

        assert_se(sd_rtnl_message_read_string(m, IFLA_IFNAME, &data) >= 0);
        assert_se(streq(data, "lo"));

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

        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);
}

static int pipe_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        int *counter = userdata;
        int r;

        (*counter) --;

        r = sd_rtnl_message_get_errno(m);

        log_info("%d left in pipe. got reply: %s", *counter, strerror(-r));

        assert_se(r >= 0);

        return 1;
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

        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);
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

        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);
}

static void test_container(void) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        uint16_t u16_data;
        uint32_t u32_data;
        char *string_data;

        assert_se(sd_rtnl_message_new_link(NULL, &m, RTM_NEWLINK, 0) >= 0);

        assert_se(sd_rtnl_message_open_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "vlan") >= 0);
        assert_se(sd_rtnl_message_append_u16(m, IFLA_VLAN_ID, 100) >= 0);
        assert_se(sd_rtnl_message_close_container(m) >= 0);
        assert_se(sd_rtnl_message_append_string(m, IFLA_INFO_KIND, "vlan") >= 0);
        assert_se(sd_rtnl_message_close_container(m) >= 0);
        assert_se(sd_rtnl_message_close_container(m) == -EINVAL);

        assert_se(sd_rtnl_message_rewind(m) >= 0);

        assert_se(sd_rtnl_message_enter_container(m, IFLA_LINKINFO) >= 0);
        assert_se(sd_rtnl_message_read_string(m, IFLA_INFO_KIND, &string_data) >= 0);
        assert_se(streq("vlan", string_data));

        assert_se(sd_rtnl_message_enter_container(m, IFLA_INFO_DATA) >= 0);
        assert_se(sd_rtnl_message_read_u16(m, IFLA_VLAN_ID, &u16_data) >= 0);
        assert_se(sd_rtnl_message_exit_container(m) >= 0);

        assert_se(sd_rtnl_message_read_string(m, IFLA_INFO_KIND, &string_data) >= 0);
        assert_se(streq("vlan", string_data));
        assert_se(sd_rtnl_message_exit_container(m) >= 0);

        assert_se(sd_rtnl_message_read_u32(m, IFLA_LINKINFO, &u32_data) < 0);

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

        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);
}

static void test_get_addresses(sd_rtnl *rtnl) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        sd_rtnl_message *m;

        assert_se(sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC) >= 0);

        assert_se(sd_rtnl_call(rtnl, req, 0, &reply) >= 0);

        for (m = reply; m; m = sd_rtnl_message_next(m)) {
                uint16_t type;
                unsigned char family, scope, flags;
                int ifindex;

                assert_se(sd_rtnl_message_get_type(m, &type) >= 0);
                assert_se(type == RTM_NEWADDR);

                assert_se(sd_rtnl_message_addr_get_ifindex(m, &ifindex) >= 0);
                assert_se(sd_rtnl_message_addr_get_family(m, &family) >= 0);
                assert_se(sd_rtnl_message_addr_get_scope(m, &scope) >= 0);
                assert_se(sd_rtnl_message_addr_get_flags(m, &flags) >= 0);

                assert_se(ifindex > 0);
                assert_se(family == AF_INET || family == AF_INET6);

                log_info("got IPv%u address on ifindex %i", family == AF_INET ? 4: 6, ifindex);
        }
}

int main(void) {
        sd_rtnl *rtnl;
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        char *string_data;
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

        test_get_addresses(rtnl);

        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_GETLINK, if_loopback) >= 0);
        assert_se(m);

        assert_se(sd_rtnl_message_get_type(m, &type) >= 0);
        assert_se(type == RTM_GETLINK);

        assert_se(sd_rtnl_message_read_string(m, IFLA_IFNAME, &string_data) == -EPERM);

        assert_se(sd_rtnl_call(rtnl, m, 0, &r) == 1);
        assert_se(sd_rtnl_message_get_type(r, &type) >= 0);
        assert_se(type == RTM_NEWLINK);

        assert_se((r = sd_rtnl_message_unref(r)) == NULL);

        assert_se(sd_rtnl_call(rtnl, m, -1, &r) == -EPERM);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);

        test_link_get(rtnl, if_loopback);
        test_address_get(rtnl, if_loopback);

        assert_se(sd_rtnl_flush(rtnl) >= 0);
        assert_se((m = sd_rtnl_message_unref(m)) == NULL);
        assert_se((r = sd_rtnl_message_unref(r)) == NULL);
        assert_se((rtnl = sd_rtnl_unref(rtnl)) == NULL);

        return EXIT_SUCCESS;
}
