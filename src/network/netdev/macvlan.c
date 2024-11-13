/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#include "conf-parser.h"
#include "macvlan.h"
#include "macvlan-util.h"
#include "networkd-network.h"
#include "parse-util.h"

typedef enum BCQueueThreshold {
        BC_QUEUE_THRESHOLD_UNDEF   = INT32_MIN,
        BC_QUEUE_THRESHOLD_DISABLE = -1,
} BCQueueThreshold;

DEFINE_CONFIG_PARSE_ENUM(config_parse_macvlan_mode, macvlan_mode, MacVlanMode);

static int netdev_macvlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        assert(netdev);
        assert(netdev->ifname);
        assert(link);
        assert(link->network);

        MacVlan *m = netdev->kind == NETDEV_KIND_MACVLAN ? MACVLAN(netdev) : MACVTAP(netdev);
        int r;

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

        if (m->bc_queue_threshold != BC_QUEUE_THRESHOLD_UNDEF) {
                r = sd_netlink_message_append_s32(req, IFLA_MACVLAN_BC_CUTOFF, m->bc_queue_threshold);
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

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        MacVlan *m = ASSERT_PTR(userdata);

        if (isempty(rvalue)) {
                m->bc_queue_length = UINT32_MAX;
                return 0;
        }

        return config_parse_uint32_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, UINT32_MAX - 1, true,
                        &m->bc_queue_length);
}

int config_parse_macvlan_broadcast_queue_threshold(
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

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        int32_t v, *threshold = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *threshold = BC_QUEUE_THRESHOLD_UNDEF;
                return 0;
        }

        if (streq(rvalue, "no")) {
                *threshold = BC_QUEUE_THRESHOLD_DISABLE;
                return 0;
        }

        r = safe_atoi32(rvalue, &v);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse %s=, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }
        if (v < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid %s= value specified, ignoring assignment: %s",
                           lvalue, rvalue);
                return 0;
        }

        *threshold = v;
        return 0;
}

static void macvlan_done(NetDev *netdev) {
        MacVlan *m = ASSERT_PTR(netdev)->kind == NETDEV_KIND_MACVLAN ? MACVLAN(netdev) : MACVTAP(netdev);

        set_free(m->match_source_mac);
}

static void macvlan_init(NetDev *netdev) {
        MacVlan *m = ASSERT_PTR(netdev)->kind == NETDEV_KIND_MACVLAN ? MACVLAN(netdev) : MACVTAP(netdev);

        m->mode = _NETDEV_MACVLAN_MODE_INVALID;
        m->bc_queue_length = UINT32_MAX;
        m->bc_queue_threshold = BC_QUEUE_THRESHOLD_UNDEF;
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
        .keep_existing = true,
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
        .keep_existing = true,
};
