/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "netlink-util.h"
#include "networkd-manager.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "hsr.h"

static const char * const hsr_protocol_table[_NETDEV_HSR_PROTOCOL_MAX] = {
        [NETDEV_HSR_PROTOCOL_HSR] = "hsr",
        [NETDEV_HSR_PROTOCOL_PRP] = "prp",
};

DEFINE_STRING_TABLE_LOOKUP(hsr_protocol, HsrProtocol);
DEFINE_CONFIG_PARSE_ENUM(config_parse_hsr_protocol, hsr_protocol, HsrProtocol);

static int hsr_get_port_links(NetDev *netdev, Link **ret1, Link **ret2) {
        Hsr *h = HSR(netdev);
        Link *link1;
        Link *link2;
        int r;

        r = link_get_by_name(netdev->manager, h->ports[0], &link1);
        if (r < 0)
                return r;

        r = link_get_by_name(netdev->manager, h->ports[1], &link2);
        if (r < 0)
                return r;

        if (ret1)
                *ret1 = link1;
        if (ret2)
                *ret2 = link2;

        return 0;
}

static int netdev_hsr_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        assert(m);

        Hsr *h = ASSERT_PTR(HSR(netdev));
        Link *link1;
        Link *link2;
        int r;

        r = hsr_get_port_links(netdev, &link1, &link2);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_HSR_SLAVE1, link1->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_HSR_SLAVE2, link2->ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_HSR_PROTOCOL, h->protocol);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_HSR_MULTICAST_SPEC, h->supervision);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_hsr_config_verify(NetDev *netdev, const char *filename) {
        assert(filename);

        Hsr *h = ASSERT_PTR(HSR(netdev));

        if (!h->ports || strv_length(h->ports) != 2) {
                return log_netdev_error_errno(
                                netdev,
                                SYNTHETIC_ERRNO(EINVAL),
                                "HSR needs two ports set in %s. Ignoring",
                                filename);
        }

        if (streq(h->ports[0], h->ports[1])) {
                return log_netdev_error_errno(
                                netdev,
                                SYNTHETIC_ERRNO(EINVAL),
                                "HSR ports must be different in %s. Ignoring",
                                filename);
        }

        return 0;
}

static int netdev_hsr_is_ready_to_create(NetDev *netdev, Link *link) {
        return hsr_get_port_links(netdev, NULL, NULL) >= 0;
}

static void netdev_hsr_done(NetDev *netdev) {
        Hsr *h = ASSERT_PTR(HSR(netdev));

        strv_free(h->ports);
}

static void netdev_hsr_init(NetDev *netdev) {
        Hsr *h = ASSERT_PTR(HSR(netdev));

        h->protocol = NETDEV_HSR_PROTOCOL_HSR;
        h->supervision = 0;
}

const NetDevVTable hsr_vtable = {
        .object_size = sizeof(Hsr),
        .init = netdev_hsr_init,
        .done = netdev_hsr_done,
        .config_verify = netdev_hsr_config_verify,
        .is_ready_to_create = netdev_hsr_is_ready_to_create,
        .fill_message_create = netdev_hsr_fill_message_create,
        .sections = NETDEV_COMMON_SECTIONS "HSR\0",
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
