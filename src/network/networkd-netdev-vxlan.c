/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2014 Susant Sahani <susant@redhat.com>

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

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "sd-rtnl.h"
#include "networkd-netdev-vxlan.h"
#include "networkd-link.h"
#include "missing.h"

static int netdev_vxlan_fill_message_create(NetDev *netdev, Link *link, sd_rtnl_message *m) {
        VxLan *v = VXLAN(netdev);
        int r;

        assert(netdev);
        assert(v);
        assert(link);
        assert(m);


        if (v->id <= VXLAN_VID_MAX) {
                r = sd_rtnl_message_append_u32(m, IFLA_VXLAN_ID, v->id);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_ID attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_append_in_addr(m, IFLA_VXLAN_GROUP, &v->group.in);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_GROUP attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_VXLAN_LINK, link->ifindex);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_LINK attribute: %s",
                                 strerror(-r));
                return r;
        }

        if(v->ttl) {
                r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_TTL, v->ttl);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_TTL attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        if(v->tos) {
                r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_TOS, v->tos);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_VXLAN_TOS attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_append_u8(m, IFLA_VXLAN_LEARNING, v->learning);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_VXLAN_LEARNING attribute: %s",
                                 strerror(-r));
                return r;
        }

        return r;
}

static int netdev_vxlan_verify(NetDev *netdev, const char *filename) {
        VxLan *v = VXLAN(netdev);

        assert(netdev);
        assert(v);
        assert(filename);

        if (v->id > VXLAN_VID_MAX) {
                log_warning("VXLAN without valid Id configured in %s. Ignoring", filename);
                return -EINVAL;
        }

        return 0;
}

static void vxlan_init(NetDev *netdev) {
        VxLan *v = VXLAN(netdev);

        assert(netdev);
        assert(v);

        v->id = VXLAN_VID_MAX + 1;
        v->learning = true;
}

const NetDevVTable vxlan_vtable = {
        .object_size = sizeof(VxLan),
        .init = vxlan_init,
        .sections = "Match\0NetDev\0VXLAN\0",
        .fill_message_create = netdev_vxlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_vxlan_verify,
};
