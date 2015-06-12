/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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


#include "sd-netlink.h"

#include "netlink-util.h"
#include "netlink-internal.h"

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name) {
        _cleanup_netlink_message_unref_ sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);
        assert(name);

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_SETLINK, ifindex);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(message, IFLA_IFNAME, name);
        if (r < 0)
                return r;

        r = sd_netlink_call(*rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int rtnl_set_link_properties(sd_netlink **rtnl, int ifindex, const char *alias,
                             const struct ether_addr *mac, unsigned mtu) {
        _cleanup_netlink_message_unref_ sd_netlink_message *message = NULL;
        int r;

        assert(rtnl);
        assert(ifindex > 0);

        if (!alias && !mac && mtu == 0)
                return 0;

        if (!*rtnl) {
                r = sd_netlink_open(rtnl);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_link(*rtnl, &message, RTM_SETLINK, ifindex);
        if (r < 0)
                return r;

        if (alias) {
                r = sd_netlink_message_append_string(message, IFLA_IFALIAS, alias);
                if (r < 0)
                        return r;
        }

        if (mac) {
                r = sd_netlink_message_append_ether_addr(message, IFLA_ADDRESS, mac);
                if (r < 0)
                        return r;
        }

        if (mtu > 0) {
                r = sd_netlink_message_append_u32(message, IFLA_MTU, mtu);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_call(*rtnl, message, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

int rtnl_message_new_synthetic_error(int error, uint32_t serial, sd_netlink_message **ret) {
        struct nlmsgerr *err;
        int r;

        assert(error <= 0);

        r = message_new(NULL, ret, NLMSG_ERROR);
        if (r < 0)
                return r;

        (*ret)->hdr->nlmsg_seq = serial;

        err = NLMSG_DATA((*ret)->hdr);

        err->error = error;

        return 0;
}

bool rtnl_message_type_is_neigh(uint16_t type) {
        switch (type) {
                case RTM_NEWNEIGH:
                case RTM_GETNEIGH:
                case RTM_DELNEIGH:
                        return true;
                default:
                        return false;
        }
}

bool rtnl_message_type_is_route(uint16_t type) {
        switch (type) {
                case RTM_NEWROUTE:
                case RTM_GETROUTE:
                case RTM_DELROUTE:
                        return true;
                default:
                        return false;
        }
}

bool rtnl_message_type_is_link(uint16_t type) {
        switch (type) {
                case RTM_NEWLINK:
                case RTM_SETLINK:
                case RTM_GETLINK:
                case RTM_DELLINK:
                        return true;
                default:
                        return false;
        }
}

bool rtnl_message_type_is_addr(uint16_t type) {
        switch (type) {
                case RTM_NEWADDR:
                case RTM_GETADDR:
                case RTM_DELADDR:
                        return true;
                default:
                        return false;
        }
}

int rtnl_log_parse_error(int r) {
        return log_error_errno(r, "Failed to parse netlink message: %m");
}

int rtnl_log_create_error(int r) {
        return log_error_errno(r, "Failed to create netlink message: %m");
}
