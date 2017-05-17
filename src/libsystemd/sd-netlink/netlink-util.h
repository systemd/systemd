#pragma once

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

#include "util.h"

int rtnl_message_new_synthetic_error(int error, uint32_t serial, sd_netlink_message **ret);
uint32_t rtnl_message_get_serial(sd_netlink_message *m);
void rtnl_message_seal(sd_netlink_message *m);

static inline bool rtnl_message_type_is_neigh(uint16_t type) {
        return IN_SET(type, RTM_NEWNEIGH, RTM_GETNEIGH, RTM_DELNEIGH);
}

static inline bool rtnl_message_type_is_route(uint16_t type) {
        return IN_SET(type, RTM_NEWROUTE, RTM_GETROUTE, RTM_DELROUTE);
}

static inline bool rtnl_message_type_is_link(uint16_t type) {
        return IN_SET(type, RTM_NEWLINK, RTM_SETLINK, RTM_GETLINK, RTM_DELLINK);
}

static inline bool rtnl_message_type_is_addr(uint16_t type) {
        return IN_SET(type, RTM_NEWADDR, RTM_GETADDR, RTM_DELADDR);
}

static inline bool rtnl_message_type_is_addrlabel(uint16_t type) {
        return IN_SET(type, RTM_NEWADDRLABEL, RTM_DELADDRLABEL, RTM_GETADDRLABEL);
}

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name);
int rtnl_set_link_properties(sd_netlink **rtnl, int ifindex, const char *alias, const struct ether_addr *mac, unsigned mtu);

int rtnl_log_parse_error(int r);
int rtnl_log_create_error(int r);
