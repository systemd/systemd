/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "ordered-set.h"

/* See struct rtvia in rtnetlink.h */
typedef struct RouteVia {
        uint16_t family;
        union in_addr_union address;
} _packed_ RouteVia;

typedef struct MultipathRoute {
        RouteVia gateway;
        uint32_t weight;
        int ifindex;
        char *ifname;
} MultipathRoute;

MultipathRoute *multipath_route_free(MultipathRoute *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(MultipathRoute*, multipath_route_free);

int multipath_route_dup(const MultipathRoute *m, MultipathRoute **ret);

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name);
int rtnl_set_link_properties(
                sd_netlink **rtnl,
                int ifindex,
                const char *alias,
                const struct hw_addr_data *hw_addr,
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
int rtnl_resolve_link_alternative_name(sd_netlink **rtnl, const char *name, char **ret);
int rtnl_resolve_ifname(sd_netlink **rtnl, const char *name);
int rtnl_resolve_interface(sd_netlink **rtnl, const char *name);
int rtnl_resolve_interface_or_warn(sd_netlink **rtnl, const char *name);
int rtnl_get_link_info(
                sd_netlink **rtnl,
                int ifindex,
                unsigned short *ret_iftype,
                unsigned *ret_flags,
                char **ret_kind,
                struct hw_addr_data *ret_hw_addr,
                struct hw_addr_data *ret_permanent_hw_addr);

int rtnl_log_parse_error(int r);
int rtnl_log_create_error(int r);

void rtattr_append_attribute_internal(struct rtattr *rta, unsigned short type, const void *data, size_t data_length);
int rtattr_append_attribute(struct rtattr **rta, unsigned short type, const void *data, size_t data_length);

int rtattr_read_nexthop(const struct rtnexthop *rtnh, size_t size, int family, OrderedSet **ret);
