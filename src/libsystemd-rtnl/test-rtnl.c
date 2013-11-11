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

static void test_link_configure(sd_rtnl *rtnl, int ifindex) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *message;
        uint16_t type;
        const char *mac = "98:fe:94:3f:c6:18", *name = "test";
        unsigned int mtu = 1450;
        void *data;

        /* we'd really like to test NEWLINK, but let's not mess with the running kernel */
        assert(sd_rtnl_message_link_new(RTM_GETLINK, ifindex, 0, 0, &message) >= 0);
        assert(sd_rtnl_message_append(message, IFLA_IFNAME, name) >= 0);
        assert(sd_rtnl_message_append(message, IFLA_ADDRESS, ether_aton(mac)) >= 0);
        assert(sd_rtnl_message_append(message, IFLA_MTU, &mtu) >= 0);

        assert(sd_rtnl_message_read(message, &type, &data) >= 0);
        assert(type == IFLA_IFNAME);
        assert(streq(name, (char *) data));

        assert(sd_rtnl_message_read(message, &type, &data) >= 0);
        assert(type == IFLA_ADDRESS);
        assert(streq(mac, ether_ntoa(data)));

        assert(sd_rtnl_message_read(message, &type, &data) >= 0);
        assert(type == IFLA_MTU);
        assert(mtu == *(unsigned int *) data);

        assert(sd_rtnl_call(rtnl, message, 0, NULL) == 0);
}

static void test_route(void) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req;
        uint32_t addr = htonl(INADDR_LOOPBACK);
        uint32_t index = 2;
        uint16_t type;
        void *data;
        int r;

        r = sd_rtnl_message_route_new(RTM_NEWROUTE, AF_INET, 0, 0, 0,
                                      RT_TABLE_MAIN, RT_SCOPE_UNIVERSE, RTPROT_BOOT,
                                      RTN_UNICAST, 0, &req);
        if (r < 0) {
                log_error("Could not create RTM_NEWROUTE message: %s", strerror(-r));
                return;
        }

        r = sd_rtnl_message_append(req, RTA_GATEWAY, &addr);
        if (r < 0) {
                log_error("Could not append RTA_GATEWAY attribute: %s", strerror(-r));
                return;
        }

        r = sd_rtnl_message_append(req, RTA_OIF, &index);
        if (r < 0) {
                log_error("Could not append RTA_OIF attribute: %s", strerror(-r));
                return;
        }

        assert(sd_rtnl_message_read(req, &type, &data) > 0);
        assert(type == RTA_GATEWAY);
        assert(*(uint32_t *) data == addr);

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

int main(void) {
        sd_rtnl *rtnl;
        sd_rtnl_message *m;
        sd_rtnl_message *r;
        void *data;
        int if_loopback;
        uint16_t type;
        unsigned int mtu = 0;
        unsigned int *mtu_reply;

        test_multiple();

        test_route();

        assert(sd_rtnl_open(0, &rtnl) >= 0);
        assert(rtnl);

        if_loopback = (int) if_nametoindex("lo");
        assert(if_loopback > 0);

        test_link_configure(rtnl, if_loopback);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, if_loopback, 0, 0, &m) >= 0);
        assert(m);

        assert(sd_rtnl_message_get_type(m, &type) >= 0);
        assert(type == RTM_GETLINK);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);

        assert(sd_rtnl_call(rtnl, m, 0, &r) >= 0);
        assert(sd_rtnl_message_get_type(r, &type) >= 0);
        assert(type == RTM_NEWLINK);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);
        assert((r = sd_rtnl_message_unref(r)) == NULL);

        assert(sd_rtnl_call(rtnl, m, -1, &r) == -EPERM);
        assert((m = sd_rtnl_message_unref(m)) == NULL);
        assert((r = sd_rtnl_message_unref(r)) == NULL);

        assert(sd_rtnl_message_link_new(RTM_GETLINK, if_loopback, 0, 0, &m) >= 0);
        assert(m);

        assert(sd_rtnl_message_append(m, IFLA_MTU, &mtu) >= 0);
        assert(sd_rtnl_message_read(m, &type, (void **) &mtu_reply) == 1);

        assert(type == IFLA_MTU);
        assert(*mtu_reply == 0);

        assert(sd_rtnl_message_read(m, &type, &data) == 0);

        assert(sd_rtnl_call(rtnl, m, -1, &r) >= 0);
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

        assert((m = sd_rtnl_message_unref(m)) == NULL);
        assert((r = sd_rtnl_message_unref(r)) == NULL);
        assert((rtnl = sd_rtnl_unref(rtnl)) == NULL);

        return EXIT_SUCCESS;
}
