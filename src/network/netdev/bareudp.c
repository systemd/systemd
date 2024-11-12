/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2020 VMware, Inc. */

#include <netinet/in.h>
#include <linux/if_arp.h>

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
DEFINE_CONFIG_PARSE_ENUM(config_parse_bare_udp_iftype, bare_udp_protocol, BareUDPProtocol);

static int netdev_bare_udp_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(m);

        BareUDP *u = BAREUDP(netdev);
        int r;

        r = sd_netlink_message_append_u16(m, IFLA_BAREUDP_ETHERTYPE, htobe16(u->iftype));
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u16(m, IFLA_BAREUDP_PORT, htobe16(u->dest_port));
        if (r < 0)
                return r;

        if (u->min_port > 0) {
                r = sd_netlink_message_append_u16(m, IFLA_BAREUDP_SRCPORT_MIN, u->min_port);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int netdev_bare_udp_verify(NetDev *netdev, const char *filename) {
        assert(filename);

        BareUDP *u = BAREUDP(netdev);

        if (u->dest_port == 0)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: BareUDP DesinationPort= is not set. Ignoring.", filename);

        if (u->iftype == _BARE_UDP_PROTOCOL_INVALID)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: BareUDP EtherType= is not set. Ignoring.", filename);

        return 0;
}

static void bare_udp_init(NetDev *netdev) {
        BareUDP *u = BAREUDP(netdev);

        u->iftype = _BARE_UDP_PROTOCOL_INVALID;
}

const NetDevVTable bare_udp_vtable = {
        .object_size = sizeof(BareUDP),
        .sections = NETDEV_COMMON_SECTIONS "BareUDP\0",
        .init = bare_udp_init,
        .config_verify = netdev_bare_udp_verify,
        .fill_message_create = netdev_bare_udp_fill_message_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_NONE,
        .keep_existing = true,
};
