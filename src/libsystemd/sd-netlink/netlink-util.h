/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/rtnetlink.h>

#include "sd-netlink.h"

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "ordered-set.h"
#include "socket-util.h"

#define RTA_FLAGS(rta) ((rta)->rta_type & ~NLA_TYPE_MASK)
#define RTA_TYPE(rta)  ((rta)->rta_type & NLA_TYPE_MASK)

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

int rtnl_set_link_name(sd_netlink **rtnl, int ifindex, const char *name, char* const* alternative_names);
static inline int rtnl_append_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names) {
        return rtnl_set_link_name(rtnl, ifindex, NULL, alternative_names);
}
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
int rtnl_set_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names);
int rtnl_set_link_alternative_names_by_ifname(sd_netlink **rtnl, const char *ifname, char* const *alternative_names);
int rtnl_delete_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names);
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

#define genl_add_match(nl, ret_slot, family, group, cmd, callback, destroy_callback, userdata, description) \
        ({                                                              \
                int (*_callback_)(sd_netlink *, sd_netlink_message *, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                sd_genl_add_match(nl, ret_slot, family, group, cmd,     \
                                  (sd_netlink_message_handler_t) _callback_, \
                                  (sd_netlink_destroy_t) _destroy_,     \
                                  userdata, description);               \
        })

int netlink_message_append_hw_addr(sd_netlink_message *m, unsigned short type, const struct hw_addr_data *data);
int netlink_message_append_in_addr_union(sd_netlink_message *m, unsigned short type, int family, const union in_addr_union *data);
int netlink_message_append_sockaddr_union(sd_netlink_message *m, unsigned short type, const union sockaddr_union *data);

int netlink_message_read_hw_addr(sd_netlink_message *m, unsigned short type, struct hw_addr_data *data);
int netlink_message_read_in_addr_union(sd_netlink_message *m, unsigned short type, int family, union in_addr_union *data);

void rtattr_append_attribute_internal(struct rtattr *rta, unsigned short type, const void *data, size_t data_length);
int rtattr_append_attribute(struct rtattr **rta, unsigned short type, const void *data, size_t data_length);

int rtattr_read_nexthop(const struct rtnexthop *rtnh, size_t size, int family, OrderedSet **ret);

void netlink_seal_message(sd_netlink *nl, sd_netlink_message *m);

size_t netlink_get_reply_callback_count(sd_netlink *nl);

/* TODO: to be exported later */
int sd_netlink_sendv(sd_netlink *nl, sd_netlink_message **messages, size_t msgcnt, uint32_t **ret_serial);
