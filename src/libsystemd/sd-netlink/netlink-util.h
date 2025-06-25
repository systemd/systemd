/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/rtnetlink.h>

#include "forward.h"
#include "in-addr-util.h"

#define RTA_FLAGS(rta) ((rta)->rta_type & ~NLA_TYPE_MASK)
#define RTA_TYPE(rta)  ((rta)->rta_type & NLA_TYPE_MASK)

/* See struct rtvia in rtnetlink.h */
typedef struct RouteVia {
        uint16_t family;
        union in_addr_union address;
} _packed_ RouteVia;

int rtnl_get_link_info_full(
                sd_netlink **rtnl,
                int ifindex,
                char **ret_name,
                char ***ret_altnames,
                unsigned short *ret_iftype,
                unsigned *ret_flags,
                char **ret_kind,
                struct hw_addr_data *ret_hw_addr,
                struct hw_addr_data *ret_permanent_hw_addr);

static inline int rtnl_get_ifname_full(sd_netlink **rtnl, int ifindex, char **ret_name, char ***ret_altnames) {
        return rtnl_get_link_info_full(
                        rtnl,
                        ifindex,
                        ret_name,
                        ret_altnames,
                        /* ret_iftype = */ NULL,
                        /* ret_flags = */ NULL,
                        /* ret_kind = */ NULL,
                        /* ret_hw_addr = */ NULL,
                        /* ret_permanent_hw_addr = */ NULL);
}
static inline int rtnl_get_ifname(sd_netlink **rtnl, int ifindex, char **ret) {
        return rtnl_get_ifname_full(rtnl, ifindex, ret, NULL);
}
static inline int rtnl_get_link_alternative_names(sd_netlink **rtnl, int ifindex, char ***ret) {
        return rtnl_get_ifname_full(rtnl, ifindex, NULL, ret);
}
static inline int rtnl_get_link_info(
                sd_netlink **rtnl,
                int ifindex,
                unsigned short *ret_iftype,
                unsigned *ret_flags,
                char **ret_kind,
                struct hw_addr_data *ret_hw_addr,
                struct hw_addr_data *ret_permanent_hw_addr) {

        return rtnl_get_link_info_full(
                        rtnl,
                        ifindex,
                        /* ret_name = */ NULL,
                        /* ret_altnames = */ NULL,
                        ret_iftype,
                        ret_flags,
                        ret_kind,
                        ret_hw_addr,
                        ret_permanent_hw_addr);
}
static inline int rtnl_get_link_hw_addr(sd_netlink **rtnl, int ifindex, struct hw_addr_data *ret) {
        return rtnl_get_link_info(
                        rtnl,
                        ifindex,
                        /* ret_iftype = */ NULL,
                        /* ret_flags = */ NULL,
                        /* ret_kind = */ NULL,
                        ret,
                        /* ret_permanent_hw_addr = */ NULL);
}

typedef enum ResolveInterfaceNameFlag {
        RESOLVE_IFNAME_MAIN        = 1 << 0, /* resolve main interface name */
        RESOLVE_IFNAME_ALTERNATIVE = 1 << 1, /* resolve alternative name */
        RESOLVE_IFNAME_NUMERIC     = 1 << 2, /* resolve decimal formatted ifindex */
        _RESOLVE_IFNAME_ALL        = RESOLVE_IFNAME_MAIN | RESOLVE_IFNAME_ALTERNATIVE | RESOLVE_IFNAME_NUMERIC,
} ResolveInterfaceNameFlag;

int rtnl_resolve_ifname_full(
                  sd_netlink **rtnl,
                  ResolveInterfaceNameFlag flags,
                  const char *name,
                  char **ret_name,
                  char ***ret_altnames);
static inline int rtnl_resolve_link_alternative_name(sd_netlink **rtnl, const char *name, char **ret) {
        return rtnl_resolve_ifname_full(rtnl, RESOLVE_IFNAME_ALTERNATIVE, name, ret, NULL);
}
static inline int rtnl_resolve_ifname(sd_netlink **rtnl, const char *name) {
        return rtnl_resolve_ifname_full(rtnl, RESOLVE_IFNAME_MAIN | RESOLVE_IFNAME_ALTERNATIVE, name, NULL, NULL);
}
static inline int rtnl_resolve_interface(sd_netlink **rtnl, const char *name) {
        return rtnl_resolve_ifname_full(rtnl, _RESOLVE_IFNAME_ALL, name, NULL, NULL);
}
int rtnl_resolve_interface_or_warn(sd_netlink **rtnl, const char *name);

int rtnl_set_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names);
int rtnl_set_link_alternative_names_by_ifname(sd_netlink **rtnl, const char *ifname, char* const *alternative_names);
int rtnl_delete_link_alternative_names(sd_netlink **rtnl, int ifindex, char* const *alternative_names);
int rtnl_rename_link(sd_netlink **rtnl, const char *orig_name, const char *new_name);
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

void netlink_seal_message(sd_netlink *nl, sd_netlink_message *m);

size_t netlink_get_reply_callback_count(sd_netlink *nl);

/* TODO: to be exported later */
int sd_netlink_sendv(sd_netlink *nl, sd_netlink_message **messages, size_t msgcnt, uint32_t **ret_serial);
