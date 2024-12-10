/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <netinet/in.h>

#include "bridge.h"
#include "netlink-util.h"
#include "networkd-manager.h"
#include "string-table.h"
#include "vlan-util.h"

assert_cc((int) MULTICAST_ROUTER_NONE            == (int) MDB_RTR_TYPE_DISABLED);
assert_cc((int) MULTICAST_ROUTER_TEMPORARY_QUERY == (int) MDB_RTR_TYPE_TEMP_QUERY);
assert_cc((int) MULTICAST_ROUTER_PERMANENT       == (int) MDB_RTR_TYPE_PERM);
assert_cc((int) MULTICAST_ROUTER_TEMPORARY       == (int) MDB_RTR_TYPE_TEMP);

static const char* const multicast_router_table[_MULTICAST_ROUTER_MAX] = {
        [MULTICAST_ROUTER_NONE]            = "no",
        [MULTICAST_ROUTER_TEMPORARY_QUERY] = "query",
        [MULTICAST_ROUTER_PERMANENT]       = "permanent",
        [MULTICAST_ROUTER_TEMPORARY]       = "temporary",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(multicast_router, MulticastRouter, _MULTICAST_ROUTER_INVALID);
DEFINE_CONFIG_PARSE_ENUM(config_parse_multicast_router, multicast_router, MulticastRouter);

/* callback for bridge netdev's parameter set */
static int netdev_bridge_set_handler(sd_netlink *rtnl, sd_netlink_message *m, NetDev *netdev) {
        int r;

        assert(netdev);
        assert(m);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_netdev_warning_errno(netdev, r, "Bridge parameters could not be set: %m");
                return 1;
        }

        log_netdev_debug(netdev, "Bridge parameters set success");

        return 1;
}

static int netdev_bridge_post_create_message(NetDev *netdev, sd_netlink_message *req) {
        Bridge *b = BRIDGE(netdev);
        struct br_boolopt_multi bm = {};
        int r;

        r = sd_netlink_message_open_container(req, IFLA_LINKINFO);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container_union(req, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
        if (r < 0)
                return r;

        /* convert to jiffes */
        if (b->forward_delay != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_FORWARD_DELAY, usec_to_jiffies(b->forward_delay));
                if (r < 0)
                        return r;
        }

        if (b->hello_time > 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_HELLO_TIME, usec_to_jiffies(b->hello_time));
                if (r < 0)
                        return r;
        }

        if (b->max_age > 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_MAX_AGE, usec_to_jiffies(b->max_age));
                if (r < 0)
                        return r;
        }

        if (b->ageing_time != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_AGEING_TIME, usec_to_jiffies(b->ageing_time));
                if (r < 0)
                        return r;
        }

        if (b->priority > 0) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_PRIORITY, b->priority);
                if (r < 0)
                        return r;
        }

        if (b->group_fwd_mask > 0) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_GROUP_FWD_MASK, b->group_fwd_mask);
                if (r < 0)
                        return r;
        }

        if (b->default_pvid != VLANID_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_VLAN_DEFAULT_PVID, b->default_pvid);
                if (r < 0)
                        return r;
        }

        if (b->mcast_querier >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_MCAST_QUERIER, b->mcast_querier);
                if (r < 0)
                        return r;
        }

        if (b->mcast_snooping >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_MCAST_SNOOPING, b->mcast_snooping);
                if (r < 0)
                        return r;
        }

        if (b->vlan_filtering >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_VLAN_FILTERING, b->vlan_filtering);
                if (r < 0)
                        return r;
        }

        if (b->vlan_protocol >= 0) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_VLAN_PROTOCOL, htobe16(b->vlan_protocol));
                if (r < 0)
                        return r;
        }

        if (b->stp >= 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_STP_STATE, b->stp);
                if (r < 0)
                        return r;
        }

        if (b->igmp_version > 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_MCAST_IGMP_VERSION, b->igmp_version);
                if (r < 0)
                        return r;
        }

        if (b->fdb_max_learned_set) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_FDB_MAX_LEARNED, b->fdb_max_learned);
                if (r < 0)
                        return r;
        }

        if (b->linklocal_learn >= 0) {
                bm.optmask |= 1 << BR_BOOLOPT_NO_LL_LEARN;
                SET_FLAG(bm.optval, 1 << BR_BOOLOPT_NO_LL_LEARN, !b->linklocal_learn);
        }

        if (bm.optmask != 0) {
                r = sd_netlink_message_append_data(req, IFLA_BR_MULTI_BOOLOPT, &bm, sizeof(bm));
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_bridge_post_create(NetDev *netdev, Link *link) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(netdev);

        if (!netdev_is_managed(netdev))
                return 0; /* Already detached, due to e.g. reloading .netdev files. */

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req, RTM_NEWLINK, netdev->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate netlink message: %m");

        r = netdev_bridge_post_create_message(netdev, req);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not create netlink message: %m");

        r = netlink_call_async(netdev->manager->rtnl, NULL, req, netdev_bridge_set_handler,
                               netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send netlink message: %m");

        netdev_ref(netdev);

        return r;
}

int config_parse_bridge_igmp_version(
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
        assert(data);

        Bridge *b = ASSERT_PTR(userdata);

        if (isempty(rvalue)) {
                b->igmp_version = 0; /* 0 means unset. */
                return 0;
        }

        return config_parse_uint8_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        2, 3, true,
                        &b->igmp_version);
}

int config_parse_bridge_port_priority(
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

        uint16_t *prio = ASSERT_PTR(data);

        return config_parse_uint16_bounded(
                        unit, filename, line, section, section_line, lvalue, rvalue,
                        0, LINK_BRIDGE_PORT_PRIORITY_MAX, true,
                        prio);
}

int config_parse_bridge_fdb_max_learned(
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

        Bridge *b = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                b->fdb_max_learned_set = false;
                return 0;
        }

        r = config_parse_uint32_bounded(unit, filename, line, section, section_line, lvalue, rvalue,
                                        0, UINT32_MAX, true, &b->fdb_max_learned);
        if (r <= 0)
                return r;

        b->fdb_max_learned_set = true;
        return 1;
}

static void bridge_init(NetDev *netdev) {
        Bridge *b = BRIDGE(netdev);

        b->mcast_querier = -1;
        b->mcast_snooping = -1;
        b->vlan_filtering = -1;
        b->vlan_protocol = -1;
        b->stp = -1;
        b->default_pvid = VLANID_INVALID;
        b->forward_delay = USEC_INFINITY;
        b->ageing_time = USEC_INFINITY;
        b->linklocal_learn = -1;
}

static bool bridge_can_set_mac(NetDev *netdev, const struct hw_addr_data *hw_addr) {
        return true;
}

const NetDevVTable bridge_vtable = {
        .object_size = sizeof(Bridge),
        .init = bridge_init,
        .sections = NETDEV_COMMON_SECTIONS "Bridge\0",
        .post_create = netdev_bridge_post_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .can_set_mac = bridge_can_set_mac,
        .iftype = ARPHRD_ETHER,
        .generate_mac = true,
};
