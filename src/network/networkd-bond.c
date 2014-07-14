/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014  Tom Gundersen <teg@jklm.no>
    Copyright 2014  Susant Sahani

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
#include <arpa/inet.h>
#include <linux/if_bonding.h>

#include "conf-parser.h"
#include "sd-rtnl.h"
#include "networkd.h"
#include "missing.h"

static const char* const bond_mode_table[_NETDEV_BOND_MODE_MAX] = {
        [NETDEV_BOND_MODE_BALANCE_RR] = "balance-rr",
        [NETDEV_BOND_MODE_ACTIVE_BACKUP] = "active-backup",
        [NETDEV_BOND_MODE_BALANCE_XOR] = "balance-xor",
        [NETDEV_BOND_MODE_BROADCAST] = "broadcast",
        [NETDEV_BOND_MODE_802_3AD] = "802.3ad",
        [NETDEV_BOND_MODE_BALANCE_TLB] = "balance-tlb",
        [NETDEV_BOND_MODE_BALANCE_ALB] = "balance-alb",
};

DEFINE_STRING_TABLE_LOOKUP(bond_mode, BondMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bond_mode, bond_mode, BondMode, "Failed to parse bond mode");

static uint8_t bond_mode_to_kernel(BondMode mode) {
        switch (mode) {
        case NETDEV_BOND_MODE_BALANCE_RR:
                return BOND_MODE_ROUNDROBIN;
        case NETDEV_BOND_MODE_ACTIVE_BACKUP:
                return BOND_MODE_ACTIVEBACKUP;
        case NETDEV_BOND_MODE_BALANCE_XOR:
                return BOND_MODE_XOR;
        case NETDEV_BOND_MODE_BROADCAST:
                return BOND_MODE_BROADCAST;
        case NETDEV_BOND_MODE_802_3AD:
                return BOND_MODE_8023AD;
        case NETDEV_BOND_MODE_BALANCE_TLB:
                return BOND_MODE_TLB;
        case NETDEV_BOND_MODE_BALANCE_ALB:
                return BOND_MODE_ALB;
        default:
                return (uint8_t) -1;
        }
}

static int netdev_fill_bond_rtnl_message(NetDev *netdev, sd_rtnl_message *m) {
        int r;

        assert(m);

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA,
                                                 netdev_kind_to_string(netdev->kind));
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->bond_mode != _NETDEV_BOND_MODE_INVALID) {
                r = sd_rtnl_message_append_u8(m, IFLA_BOND_MODE,
                                              bond_mode_to_kernel(netdev->bond_mode));
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_BOND_MODE attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

int netdev_create_bond(NetDev *netdev, sd_rtnl_message_handler_t callback) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        int r;

        assert(netdev);
        assert(netdev->kind == NETDEV_KIND_BOND);
        assert(netdev->ifname);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_NEWLINK message: %s",
                                 strerror(-r));
                return r;
        }

        r = netdev_fill_bond_rtnl_message(netdev, m);
        if(r < 0)
                return r;

        r = sd_rtnl_call_async(netdev->manager->rtnl, m, callback, netdev, 0, NULL);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        netdev_ref(netdev);

        log_debug_netdev(netdev, "Creating bond netdev: %s",
                         netdev_kind_to_string(netdev->kind));

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}
