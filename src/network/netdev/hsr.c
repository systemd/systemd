/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "hsr.h"
#include "string-table.h"

static const char* const hsr_protocol_table[_NETDEV_HSR_PROTOCOL_MAX] = {
        [NETDEV_HSR_PROTOCOL_HSR] = "HSR",
        [NETDEV_HSR_PROTOCOL_PRP] = "PRP",
};

DEFINE_STRING_TABLE_LOOKUP(hsr_protocol, HsrProtocol);
DEFINE_CONFIG_PARSE_ENUM(config_parse_hsr_protocol, hsr_protocol, HsrProtocol,
                         "Failed to parse Protocol=");

static int netdev_hsr_get_iface_indexes(Hsr *hsr, int *indexes) {
        Link *link = NULL;
        int r, i;

        assert(hsr);

        for (i = 0; i < _NETDEV_HSR_SLAVE_MAX; i++) {
                r = link_get_by_name(hsr->meta.manager, hsr->slave_ifaces[i], &link);
                if (r < 0)
                        return r;

                if (indexes)
                        indexes[i] = link->ifindex;
        }

        return 0;
}

static int netdev_hsr_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        Hsr *hsr;
        int indexes[_NETDEV_HSR_SLAVE_MAX];
        int r;

        assert(netdev);
        assert(!link);
        assert(m);

        hsr = HSR(netdev);

        assert(hsr);

        r = netdev_hsr_get_iface_indexes(hsr, indexes);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_HSR_SLAVE1, indexes[NETDEV_HSR_SLAVE1]);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, IFLA_HSR_SLAVE2, indexes[NETDEV_HSR_SLAVE2]);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(m, IFLA_HSR_MULTICAST_SPEC, hsr->multicast_spec);
        if (r < 0)
                return r;

        /* Protocol version is not supported by kernel module when PRP is used. */
        if (hsr->protocol == NETDEV_HSR_PROTOCOL_HSR) {
                r = sd_netlink_message_append_u8(m, IFLA_HSR_VERSION, hsr->version);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_append_u8(m, IFLA_HSR_PROTOCOL, hsr->protocol);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_hsr_verify(NetDev *netdev, const char *filename) {
        Hsr *hsr;
        int i;

        assert(netdev);
        assert(filename);

        hsr = HSR(netdev);

        assert(hsr);

        for (i = 0; i < _NETDEV_HSR_SLAVE_MAX; i++) {
                if (!hsr->slave_ifaces[i])
                        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                        "HSR without SlaveInterface%d= configured in %s. Ignoring",
                                                        (i + 1), filename);
        }

        if (streq(hsr->slave_ifaces[NETDEV_HSR_SLAVE1], hsr->slave_ifaces[NETDEV_HSR_SLAVE2]))
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "SlaveInterface1= and SlaveInterface2= must be different in %s. Ignoring",
                                                filename);

        return 0;
}

static int netdev_hsr_is_ready_to_create(NetDev *netdev, Link *link) {
        Hsr *hsr;

        assert(netdev);

        hsr = HSR(netdev);

        assert(hsr);

        return netdev_hsr_get_iface_indexes(hsr, NULL) >= 0;
}

static void netdev_hsr_done(NetDev *netdev) {
        Hsr *hsr;
        int i;

        assert(netdev);

        hsr = HSR(netdev);

        assert(hsr);

        for (i = 0; i < _NETDEV_HSR_SLAVE_MAX; i++)
                free(hsr->slave_ifaces[i]);
}

const NetDevVTable hsr_vtable = {
        .object_size = sizeof(Hsr),
        .sections = NETDEV_COMMON_SECTIONS "HSR\0",
        .fill_message_create = netdev_hsr_fill_message_create,
        .config_verify = netdev_hsr_verify,
        .is_ready_to_create = netdev_hsr_is_ready_to_create,
        .done = netdev_hsr_done,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
