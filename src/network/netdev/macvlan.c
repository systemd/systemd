/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "conf-parser.h"
#include "macvlan.h"
#include "macvlan-util.h"
#include "networkd-network.h"
#include "parse-util.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_macvlan_mode, macvlan_mode, MacVlanMode, "Failed to parse macvlan mode");

static int netdev_macvlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        MacVlan *m;
        int r;

        assert(netdev);
        assert(link);
        assert(netdev->ifname);
        assert(link->network);

        if (netdev->kind == NETDEV_KIND_MACVLAN)
                m = MACVLAN(netdev);
        else
                m = MACVTAP(netdev);

        assert(m);

        if (m->mode == NETDEV_MACVLAN_MODE_SOURCE && !set_isempty(m->match_source_mac)) {
                const struct ether_addr *mac_addr;

                r = sd_netlink_message_append_u32(req, IFLA_MACVLAN_MACADDR_MODE, MACVLAN_MACADDR_SET);
                if (r < 0)
                        return r;

                r = sd_netlink_message_open_container(req, IFLA_MACVLAN_MACADDR_DATA);
                if (r < 0)
                        return r;

                SET_FOREACH(mac_addr, m->match_source_mac) {
                        r = sd_netlink_message_append_ether_addr(req, IFLA_MACVLAN_MACADDR, mac_addr);
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        if (m->mode != _NETDEV_MACVLAN_MODE_INVALID) {
                r = sd_netlink_message_append_u32(req, IFLA_MACVLAN_MODE, m->mode);
                if (r < 0)
                        return r;
        }

        /* set the nopromisc flag if Promiscuous= of the link is explicitly set to false */
        if (m->mode == NETDEV_MACVLAN_MODE_PASSTHRU && link->network->promiscuous == 0) {
                r = sd_netlink_message_append_u16(req, IFLA_MACVLAN_FLAGS, MACVLAN_FLAG_NOPROMISC);
                if (r < 0)
                        return r;
        }

        if (m->bc_queue_length != UINT32_MAX) {
                r = sd_netlink_message_append_u32(req, IFLA_MACVLAN_BC_QUEUE_LEN, m->bc_queue_length);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_parse_macvlan_broadcast_queue_size(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        MacVlan *m = ASSERT_PTR(userdata);
        uint32_t v;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                m->bc_queue_length = UINT32_MAX;
                return 0;
        }

        r = safe_atou32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse BroadcastMulticastQueueLength=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        if (v == UINT32_MAX) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid BroadcastMulticastQueueLength=%s, ignoring assignment: %m", rvalue);
                return 0;
        }

        m->bc_queue_length = v;
        return 0;
}

static void macvlan_done(NetDev *n) {
        MacVlan *m;

        assert(n);

        if (n->kind == NETDEV_KIND_MACVLAN)
                m = MACVLAN(n);
        else
                m = MACVTAP(n);

        assert(m);

        set_free(m->match_source_mac);
}

static void macvlan_init(NetDev *n) {
        MacVlan *m;

        assert(n);

        if (n->kind == NETDEV_KIND_MACVLAN)
                m = MACVLAN(n);
        else
                m = MACVTAP(n);

        assert(m);

        m->mode = _NETDEV_MACVLAN_MODE_INVALID;
        m->bc_queue_length = UINT32_MAX;
}

const NetDevVTable macvtap_vtable = {
        .object_size = sizeof(MacVlan),
        .init = macvlan_init,
        .done = macvlan_done,
        .sections = NETDEV_COMMON_SECTIONS "MACVTAP\0",
        .fill_message_create = netdev_macvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};

const NetDevVTable macvlan_vtable = {
        .object_size = sizeof(MacVlan),
        .init = macvlan_init,
        .done = macvlan_done,
        .sections = NETDEV_COMMON_SECTIONS "MACVLAN\0",
        .fill_message_create = netdev_macvlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
