/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "conf-parser.h"
#include "ipvlan.h"
#include "ipvlan-util.h"
#include "networkd-link.h"
#include "string-util.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_ipvlan_mode, ipvlan_mode, IPVlanMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_ipvlan_flags, ipvlan_flags, IPVlanFlags);

static int netdev_ipvlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        assert(netdev);
        assert(link);
        assert(netdev->ifname);

        IPVlan *m = netdev->kind == NETDEV_KIND_IPVLAN ? IPVLAN(netdev) : IPVTAP(netdev);
        int r;

        if (m->mode != _NETDEV_IPVLAN_MODE_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_IPVLAN_MODE, m->mode);
                if (r < 0)
                        return r;
        }

        if (m->flags != _NETDEV_IPVLAN_FLAGS_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_IPVLAN_FLAGS, m->flags);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool ipvlan_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        assert(netdev);

        /* MAC address cannot be updated. Even unchanged, IFLA_ADDRESS attribute cannot be set in the message. */
        return netdev->ifindex <= 0;
}

static void ipvlan_init(NetDev *netdev) {
        IPVlan *m = ASSERT_PTR(netdev)->kind == NETDEV_KIND_IPVLAN ? IPVLAN(netdev) : IPVTAP(netdev);

        m->mode = _NETDEV_IPVLAN_MODE_INVALID;
        m->flags = _NETDEV_IPVLAN_FLAGS_INVALID;
}

const NetDevVTable ipvlan_vtable = {
        .object_size = sizeof(IPVlan),
        .init = ipvlan_init,
        .sections = NETDEV_COMMON_SECTIONS "IPVLAN\0",
        .fill_message_create = netdev_ipvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .can_set_mac = ipvlan_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .keep_existing = true,
};

const NetDevVTable ipvtap_vtable = {
        .object_size = sizeof(IPVlan),
        .init = ipvlan_init,
        .sections = NETDEV_COMMON_SECTIONS "IPVTAP\0",
        .fill_message_create = netdev_ipvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .can_set_mac = ipvlan_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
        .keep_existing = true,
};

IPVlanMode link_get_ipvlan_mode(Link *link) {
        assert(link);

        if (!link->netdev || link->netdev->kind != NETDEV_KIND_IPVLAN)
                return _NETDEV_IPVLAN_MODE_INVALID;

        return IPVLAN(link->netdev)->mode;
}
