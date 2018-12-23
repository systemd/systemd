/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>

#include "missing.h"
#include "netlink-util.h"
#include "netdev/bridge.h"
#include "networkd-manager.h"
#include "vlan-util.h"

/* callback for brige netdev's parameter set */
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

static int netdev_bridge_post_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        Bridge *b;
        int r;

        assert(netdev);

        b = BRIDGE(netdev);

        assert(b);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req, RTM_NEWLINK, netdev->ifindex);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not allocate RTM_SETLINK message: %m");

        r = sd_netlink_message_set_flags(req, NLM_F_REQUEST | NLM_F_ACK);
        if (r < 0)
                return log_link_error_errno(link, r, "Could not set netlink flags: %m");

        r = sd_netlink_message_open_container(req, IFLA_LINKINFO);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_PROTINFO attribute: %m");

        r = sd_netlink_message_open_container_union(req, IFLA_INFO_DATA, netdev_kind_to_string(netdev->kind));
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        /* convert to jiffes */
        if (b->forward_delay != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_FORWARD_DELAY, usec_to_jiffies(b->forward_delay));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_FORWARD_DELAY attribute: %m");
        }

        if (b->hello_time > 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_HELLO_TIME, usec_to_jiffies(b->hello_time));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_HELLO_TIME attribute: %m");
        }

        if (b->max_age > 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_MAX_AGE, usec_to_jiffies(b->max_age));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_MAX_AGE attribute: %m");
        }

        if (b->ageing_time != USEC_INFINITY) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_AGEING_TIME, usec_to_jiffies(b->ageing_time));
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_AGEING_TIME attribute: %m");
        }

        if (b->priority > 0) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_PRIORITY, b->priority);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_PRIORITY attribute: %m");
        }

        if (b->group_fwd_mask > 0) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_GROUP_FWD_MASK, b->group_fwd_mask);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_GROUP_FWD_MASK attribute: %m");
        }

        if (b->default_pvid != VLANID_INVALID) {
                r = sd_netlink_message_append_u16(req, IFLA_BR_VLAN_DEFAULT_PVID, b->default_pvid);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_VLAN_DEFAULT_PVID attribute: %m");
        }

        if (b->mcast_querier >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_MCAST_QUERIER, b->mcast_querier);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_MCAST_QUERIER attribute: %m");
        }

        if (b->mcast_snooping >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_MCAST_SNOOPING, b->mcast_snooping);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_MCAST_SNOOPING attribute: %m");
        }

        if (b->vlan_filtering >= 0) {
                r = sd_netlink_message_append_u8(req, IFLA_BR_VLAN_FILTERING, b->vlan_filtering);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_VLAN_FILTERING attribute: %m");
        }

        if (b->stp >= 0) {
                r = sd_netlink_message_append_u32(req, IFLA_BR_STP_STATE, b->stp);
                if (r < 0)
                        return log_netdev_error_errno(netdev, r, "Could not append IFLA_BR_STP_STATE attribute: %m");
        }

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = netlink_call_async(netdev->manager->rtnl, NULL, req, netdev_bridge_set_handler, netdev_destroy_callback, netdev);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

        netdev_ref(netdev);

        return r;
}

static void bridge_init(NetDev *n) {
        Bridge *b;

        b = BRIDGE(n);

        assert(b);

        b->mcast_querier = -1;
        b->mcast_snooping = -1;
        b->vlan_filtering = -1;
        b->stp = -1;
        b->default_pvid = VLANID_INVALID;
        b->forward_delay = USEC_INFINITY;
        b->ageing_time = USEC_INFINITY;
}

const NetDevVTable bridge_vtable = {
        .object_size = sizeof(Bridge),
        .init = bridge_init,
        .sections = "Match\0NetDev\0Bridge\0",
        .post_create = netdev_bridge_post_create,
        .create_type = NETDEV_CREATE_MASTER,
};
