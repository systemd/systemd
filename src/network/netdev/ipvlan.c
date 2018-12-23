/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "conf-parser.h"
#include "netdev/ipvlan.h"
#include "string-table.h"

static const char *const ipvlan_mode_table[_NETDEV_IPVLAN_MODE_MAX] = {
        [NETDEV_IPVLAN_MODE_L2] = "L2",
        [NETDEV_IPVLAN_MODE_L3] = "L3",
        [NETDEV_IPVLAN_MODE_L3S] = "L3S",
};

DEFINE_STRING_TABLE_LOOKUP(ipvlan_mode, IPVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipvlan_mode, ipvlan_mode, IPVlanMode, "Failed to parse ipvlan mode");

static const char *const ipvlan_flags_table[_NETDEV_IPVLAN_FLAGS_MAX] = {
        [NETDEV_IPVLAN_FLAGS_BRIGDE] = "bridge",
        [NETDEV_IPVLAN_FLAGS_PRIVATE] = "private",
        [NETDEV_IPVLAN_FLAGS_VEPA] = "vepa",
};

DEFINE_STRING_TABLE_LOOKUP(ipvlan_flags, IPVlanFlags);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipvlan_flags, ipvlan_flags, IPVlanFlags, "Failed to parse ipvlan flags");

static int netdev_ipvlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        IPVlan *m;
        int r;

        assert(netdev);
        assert(link);
        assert(netdev->ifname);

        m = IPVLAN(netdev);

        assert(m);

        if (m->mode != _NETDEV_IPVLAN_MODE_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_IPVLAN_MODE, m->mode);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPVLAN_MODE attribute: %m");
        }

        if (m->flags != _NETDEV_IPVLAN_FLAGS_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_IPVLAN_FLAGS, m->flags);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_IPVLAN_FLAGS attribute: %m");
        }

        return 0;
}

static void ipvlan_init(NetDev *n) {
        IPVlan *m;

        assert(n);

        m = IPVLAN(n);

        assert(m);

        m->mode = _NETDEV_IPVLAN_MODE_INVALID;
        m->flags = _NETDEV_IPVLAN_FLAGS_INVALID;
}

const NetDevVTable ipvlan_vtable = {
        .object_size = sizeof(IPVlan),
        .init = ipvlan_init,
        .sections = "Match\0NetDev\0IPVLAN\0",
        .fill_message_create = netdev_ipvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
};
