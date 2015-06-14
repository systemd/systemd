/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Susant Sahani

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

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <libkmod.h>

#include "util.h"
#include "macro.h"
#include "sd-netlink.h"

static int load_module(const char *mod_name) {
        struct kmod_ctx *ctx;
        struct kmod_list *list = NULL, *l;
        int r;

        ctx = kmod_new(NULL, NULL);
        if (!ctx) {
                kmod_unref(ctx);
                return -ENOMEM;
        }

        r = kmod_module_new_from_lookup(ctx, mod_name, &list);
        if (r < 0)
                return -1;

        kmod_list_foreach(l, list) {
                struct kmod_module *mod = kmod_module_get_module(l);

                r = kmod_module_probe_insert_module(mod, 0, NULL, NULL, NULL, NULL);
                if (r >= 0)
                        r = 0;
                else
                        r = -1;

                kmod_module_unref(mod);
        }

        kmod_module_unref_list(list);
        kmod_unref(ctx);

        return r;
}

static int test_tunnel_configure(sd_netlink *rtnl) {
        int r;
        sd_netlink_message *m, *n;
        struct in_addr local, remote;

        /* skip test if module cannot be loaded */
        r = load_module("ipip");
        if(r < 0)
                return EXIT_TEST_SKIP;

        if(getuid() != 0)
                return EXIT_TEST_SKIP;

        /* IPIP tunnel */
        assert_se(sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0) >= 0);
        assert_se(m);

        assert_se(sd_netlink_message_append_string(m, IFLA_IFNAME, "ipip-tunnel") >= 0);
        assert_se(sd_netlink_message_append_u32(m, IFLA_MTU, 1234)>= 0);

        assert_se(sd_netlink_message_open_container(m, IFLA_LINKINFO) >= 0);

        assert_se(sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, "ipip") >= 0);

        inet_pton(AF_INET, "192.168.21.1", &local.s_addr);
        assert_se(sd_netlink_message_append_u32(m, IFLA_IPTUN_LOCAL, local.s_addr) >= 0);

        inet_pton(AF_INET, "192.168.21.2", &remote.s_addr);
        assert_se(sd_netlink_message_append_u32(m, IFLA_IPTUN_REMOTE, remote.s_addr) >= 0);

        assert_se(sd_netlink_message_close_container(m) >= 0);
        assert_se(sd_netlink_message_close_container(m) >= 0);

        assert_se(sd_netlink_call(rtnl, m, -1, 0) == 1);

        assert_se((m = sd_netlink_message_unref(m)) == NULL);

        r = load_module("sit");
        if(r < 0)
                return EXIT_TEST_SKIP;

        /* sit */
        assert_se(sd_rtnl_message_new_link(rtnl, &n, RTM_NEWLINK, 0) >= 0);
        assert_se(n);

        assert_se(sd_netlink_message_append_string(n, IFLA_IFNAME, "sit-tunnel") >= 0);
        assert_se(sd_netlink_message_append_u32(n, IFLA_MTU, 1234)>= 0);

        assert_se(sd_netlink_message_open_container(n, IFLA_LINKINFO) >= 0);

        assert_se(sd_netlink_message_open_container_union(n, IFLA_INFO_DATA, "sit") >= 0);

        assert_se(sd_netlink_message_append_u8(n, IFLA_IPTUN_PROTO, IPPROTO_IPIP) >= 0);

        inet_pton(AF_INET, "192.168.21.3", &local.s_addr);
        assert_se(sd_netlink_message_append_u32(n, IFLA_IPTUN_LOCAL, local.s_addr) >= 0);

        inet_pton(AF_INET, "192.168.21.4", &remote.s_addr);
        assert_se(sd_netlink_message_append_u32(n, IFLA_IPTUN_REMOTE, remote.s_addr) >= 0);

        assert_se(sd_netlink_message_close_container(n) >= 0);
        assert_se(sd_netlink_message_close_container(n) >= 0);

        assert_se(sd_netlink_call(rtnl, n, -1, 0) == 1);

        assert_se((n = sd_netlink_message_unref(n)) == NULL);

        return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
        sd_netlink *rtnl;
        int r;

        assert_se(sd_netlink_open(&rtnl) >= 0);
        assert_se(rtnl);

        r = test_tunnel_configure(rtnl);

        assert_se((rtnl = sd_netlink_unref(rtnl)) == NULL);

        return r;
}
