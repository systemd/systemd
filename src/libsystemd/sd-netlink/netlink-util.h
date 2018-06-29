/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-netlink.h"

#include "util.h"

int rtnl_message_new_synthetic_error(sd_netlink *rtnl, int error, uint32_t serial, sd_netlink_message **ret);
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

static inline bool rtnl_message_type_is_routing_policy_rule(uint16_t type) {
        return IN_SET(type, RTM_NEWRULE, RTM_DELRULE, RTM_GETRULE);
}

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name);
int rtnl_set_link_properties(sd_netlink **rtnl, int ifindex, const char *alias, const struct ether_addr *mac, uint32_t mtu);

int rtnl_log_parse_error(int r);
int rtnl_log_create_error(int r);
