/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include "bareudp.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "string-table.h"

static const char* const bare_udp_protocol_table[_BARE_UDP_PROTOCOL_MAX] = {
        [BARE_UDP_PROTOCOL_IPV4]    = "ipv4",
        [BARE_UDP_PROTOCOL_IPV6]    = "ipv6",
        [BARE_UDP_PROTOCOL_MPLS_UC] = "mpls-uc",
        [BARE_UDP_PROTOCOL_MPLS_MC] = "mpls-mc",
};

DEFINE_STRING_TABLE_LOOKUP(bare_udp_protocol, BareUDPProtocol);
DEFINE_CONFIG_PARSE_ENUM(config_parse_bare_udp_iftype, bare_udp_protocol, BareUDPProtocol,
                         "Failed to parse EtherType=");

/* callback for bareudp netdev's created without a backing Link */
static int bare_udp_netdev_create_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(netdev->state != _NETDEV_STATE_INVALID);

        r = sd_netlink_message_get_errno(m);
        if (r == -EEXIST)
                log_netdev_info(netdev, "BareUDP netdev exists, using existing without changing its parameters.");
        else if (r < 0) {
                log_netdev_warning_errno(netdev, r, "BareUDP netdev could not be created: %m");
                netdev_drop(netdev);

                return 1;
        }

        log_netdev_debug(netdev, "BareUDP created.");

        return 1;
}

static int netdev_bare_udp_create(NetDev *netdev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        BareUDP *u;
        int r;

        assert(netdev);

        u = BAREUDP(netdev);

        assert(u);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate RTM_NEWLINK message: %m");

        r = sd_netlink_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_IFNAME, attribute: %m");

        r = sd_netlink_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_message_open_container_union(m, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = sd_netlink_message_append_u16(m, IFLA_BAREUDP_ETHERTYPE, htobe16(u->iftype));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BAREUDP_ETHERTYPE attribute: %m");

        r = sd_netlink_message_append_u16(m, IFLA_BAREUDP_PORT, htobe16(u->dest_port));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_BAREUDP_PORT attribute: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = netlink_call_async(netdev->manager->rtnl, NULL, m, bare_udp_netdev_create_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

        netdev_ref(netdev);
        netdev->state = NETDEV_STATE_CREATING;

        log_netdev_debug(netdev, "Creating");

        return r;
}

static int netdev_bare_udp_verify(NetDev *netdev, const char *filename) {
        BareUDP *u;

        assert(netdev);
        assert(filename);

        u = BAREUDP(netdev);

        assert(u);

        if (u->dest_port == 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: BareUDP DesinationPort= is not set. Ignoring.", filename);

        if (u->iftype == _BARE_UDP_PROTOCOL_INVALID)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: BareUDP EtherType= is not set. Ignoring.", filename);

        return 0;
}

static void bare_udp_init(NetDev *netdev) {
        BareUDP *u;

        assert(netdev);

        u = BAREUDP(netdev);

        assert(u);

        u->iftype = _BARE_UDP_PROTOCOL_INVALID;
}

const NetDevVTable bare_udp_vtable = {
        .object_size = sizeof(BareUDP),
        .sections = NETDEV_COMMON_SECTIONS "BareUDP\0",
        .init = bare_udp_init,
        .config_verify = netdev_bare_udp_verify,
        .create = netdev_bare_udp_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
};
