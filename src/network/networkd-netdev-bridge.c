/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014  Tom Gundersen <teg@jklm.no>
    Copyright 2014  Susant Sahani

    systemd is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    systemd is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <net/if.h>

#include "missing.h"
#include "netlink-util.h"
#include "networkd-netdev-bridge.h"

/* callback for brige netdev's parameter set */
static int netdev_bridge_set_handler(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        _cleanup_netdev_unref_ NetDev *netdev = userdata;
        int r;

        assert(netdev);
        assert(m);

        r = sd_netlink_message_get_errno(m);
        if (r < 0) {
                log_netdev_warning_errno(netdev, r, "Bridge parameters could not be set: %m");
                return 1;
        }

        log_netdev_debug(netdev, "Bridge parametres set success");

        return 1;
}

static int netdev_bridge_post_create(NetDev *netdev, Link *link, sd_netlink_message *m) {
        _cleanup_netlink_message_unref_ sd_netlink_message *req = NULL;
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
        if (b->forward_delay > 0) {
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

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_LINKINFO attribute: %m");

        r = sd_netlink_message_close_container(req);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not append IFLA_INFO_DATA attribute: %m");

        r = sd_netlink_call_async(netdev->manager->rtnl, req, netdev_bridge_set_handler, netdev, 0, NULL);
        if (r < 0)
                return log_netdev_error_errno(netdev, r, "Could not send rtnetlink message: %m");

        netdev_ref(netdev);

        return r;
}

const NetDevVTable bridge_vtable = {
        .object_size = sizeof(Bridge),
        .sections = "Match\0NetDev\0Bridge\0",
        .post_create = netdev_bridge_post_create,
        .create_type = NETDEV_CREATE_MASTER,
};
