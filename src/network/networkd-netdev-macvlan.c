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

#include <net/if.h>

#include "networkd-netdev-macvlan.h"
#include "network-internal.h"
#include "conf-parser.h"
#include "list.h"

static const char* const macvlan_mode_table[_NETDEV_MACVLAN_MODE_MAX] = {
        [NETDEV_MACVLAN_MODE_PRIVATE] = "private",
        [NETDEV_MACVLAN_MODE_VEPA] = "vepa",
        [NETDEV_MACVLAN_MODE_BRIDGE] = "bridge",
        [NETDEV_MACVLAN_MODE_PASSTHRU] = "passthru",
};

DEFINE_STRING_TABLE_LOOKUP(macvlan_mode, MacVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_macvlan_mode, macvlan_mode, MacVlanMode, "Failed to parse macvlan mode");

static int netdev_macvlan_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *req) {
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_MACVLAN);
        assert(link);
        assert(netdev->ifname);

        r = sd_rtnl_message_append_u32(req, IFLA_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(req, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->mtu) {
                r = sd_rtnl_message_append_u32(req, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(req, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Colud not append IFLA_ADDRESS attribute: %s",
                                         strerror(-r));
                    return r;
                }
        }

        r = sd_rtnl_message_open_container(req, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not open IFLA_LINKINFO container: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(req, IFLA_INFO_DATA, "macvlan");
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not open IFLA_INFO_DATA container: %s",
                                  strerror(-r));
                return r;
        }

        if (netdev->macvlan_mode != _NETDEV_MACVLAN_MODE_INVALID) {
        r = sd_rtnl_message_append_u32(req, IFLA_MACVLAN_MODE, netdev->macvlan_mode);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_MACVLAN_MODE attribute: %s",
                                 strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not close IFLA_INFO_DATA container %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not close IFLA_LINKINFO container %s",
                                 strerror(-r));
                return r;
        }

        return 0;
}

const NetDevVTable macvlan_vtable = {
        .fill_message_create_on_link = netdev_macvlan_fill_message_create,
};
