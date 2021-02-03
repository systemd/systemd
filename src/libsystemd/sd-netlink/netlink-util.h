/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/rtnetlink.h>

#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "ordered-set.h"
#include "socket-util.h"
#include "util.h"

/* See struct rtvia in rtnetlink.h */
typedef struct RouteVia {
        uint16_t family;
        union in_addr_union address;
} _packed_ RouteVia;

typedef struct MultipathRoute {
        RouteVia gateway;
        int ifindex;
        uint32_t weight;
} MultipathRoute;

int rtnl_message_new_synthetic_error(sd_netlink *rtnl, int error, uint32_t serial, sd_netlink_message **ret);
uint32_t rtnl_message_get_serial(sd_netlink_message *m);
void rtnl_message_seal(sd_netlink_message *m);

static inline bool rtnl_message_type_is_neigh(uint16_t type) {
        return IN_SET(type, RTM_NEWNEIGH, RTM_GETNEIGH, RTM_DELNEIGH);
}

static inline bool rtnl_message_type_is_route(uint16_t type) {
        return IN_SET(type, RTM_NEWROUTE, RTM_GETROUTE, RTM_DELROUTE);
}

static inline bool rtnl_message_type_is_nexthop(uint16_t type) {
        return IN_SET(type, RTM_NEWNEXTHOP, RTM_GETNEXTHOP, RTM_DELNEXTHOP);
}

static inline bool rtnl_message_type_is_link(uint16_t type) {
        return IN_SET(type,
                      RTM_NEWLINK, RTM_SETLINK, RTM_GETLINK, RTM_DELLINK,
                      RTM_NEWLINKPROP, RTM_DELLINKPROP, RTM_GETLINKPROP);
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

static inline bool rtnl_message_type_is_qdisc(uint16_t type) {
        return IN_SET(type, RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC);
}

static inline bool rtnl_message_type_is_tclass(uint16_t type) {
        return IN_SET(type, RTM_NEWTCLASS, RTM_DELTCLASS, RTM_GETTCLASS);
}

static inline bool rtnl_message_type_is_mdb(uint16_t type) {
        return IN_SET(type, RTM_NEWMDB, RTM_DELMDB, RTM_GETMDB);
}

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name);
int rtnl_set_link_properties(
                sd_netlink **rtnl,
                int ifindex,
                const char *alias,
                const struct ether_addr *mac,
                uint32_t txqueues,
                uint32_t rxqueues,
                uint32_t txqueuelen,
                uint32_t mtu,
                uint32_t gso_max_size,
                size_t gso_max_segments);
int rtnl_get_link_alternative_names(sd_netlink **rtnl, int ifindex, char ***ret);
int rtnl_set_link_alternative_names(sd_netlink **rtnl, int ifindex, char * const *alternative_names);
int rtnl_set_link_alternative_names_by_ifname(sd_netlink **rtnl, const char *ifname, char * const *alternative_names);
int rtnl_delete_link_alternative_names(sd_netlink **rtnl, int ifindex, char * const *alternative_names);
int rtnl_resolve_link_alternative_name(sd_netlink **rtnl, const char *name);
int rtnl_get_link_iftype(sd_netlink **rtnl, int ifindex, unsigned short *ret);

int rtnl_log_parse_error(int r);
int rtnl_log_create_error(int r);

#define netlink_call_async(nl, ret_slot, message, callback, destroy_callback, userdata) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_netlink_call_async(nl, ret_slot, message,            \
                                      (sd_netlink_message_handler_t) _callback_, \
                                      (sd_netlink_destroy_t) _destroy_, \
                                      userdata, 0, __func__);           \
        })

#define netlink_add_match(nl, ret_slot, match, callback, destroy_callback, userdata, description) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_netlink_add_match(nl, ret_slot, match,               \
                                     (sd_netlink_message_handler_t) _callback_, \
                                     (sd_netlink_destroy_t) _destroy_,  \
                                     userdata, description);            \
        })

int netlink_message_append_hw_addr(sd_netlink_message *m, unsigned short type, const hw_addr_data *data);
int netlink_message_append_in_addr_union(sd_netlink_message *m, unsigned short type, int family, const union in_addr_union *data);
int netlink_message_append_sockaddr_union(sd_netlink_message *m, unsigned short type, const union sockaddr_union *data);

int netlink_message_read_hw_addr(sd_netlink_message *m, unsigned short type, hw_addr_data *data);
int netlink_message_read_in_addr_union(sd_netlink_message *m, unsigned short type, int family, union in_addr_union *data);

void rtattr_append_attribute_internal(struct rtattr *rta, unsigned short type, const void *data, size_t data_length);
int rtattr_append_attribute(struct rtattr **rta, unsigned short type, const void *data, size_t data_length);

int rtattr_read_nexthop(const struct rtnexthop *rtnh, size_t size, int family, OrderedSet **ret);
