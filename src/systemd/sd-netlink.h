/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdnetlinkhfoo
#define foosdnetlinkhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <linux/rtnetlink.h> /* IWYU pragma: export */

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

struct ether_addr;
struct in_addr;
struct in6_addr;
struct sockaddr_in;
struct sockaddr_in6;
struct sock_filter;
struct ifa_cacheinfo;

typedef struct sd_event sd_event;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;

/* callback */
typedef int (*sd_netlink_message_handler_t)(sd_netlink *nl, sd_netlink_message *m, void *userdata);
typedef _sd_destroy_t sd_netlink_destroy_t;

/* bus */
int sd_netlink_open(sd_netlink **ret);
int sd_netlink_open_fd(sd_netlink **ret, int fd);
int sd_netlink_increase_rxbuf(sd_netlink *nl, const size_t size);

sd_netlink* sd_netlink_ref(sd_netlink *nl);
sd_netlink* sd_netlink_unref(sd_netlink *nl);

int sd_netlink_send(sd_netlink *nl, sd_netlink_message *message, uint32_t *ret_serial);
int sd_netlink_call_async(sd_netlink *nl, sd_netlink_slot **ret_slot, sd_netlink_message *message,
                          sd_netlink_message_handler_t callback, sd_netlink_destroy_t destroy_callback,
                          void *userdata, uint64_t usec, const char *description);
int sd_netlink_call(sd_netlink *nl, sd_netlink_message *message, uint64_t timeout, sd_netlink_message **ret);
int sd_netlink_read(sd_netlink *nl, uint32_t serial, uint64_t timeout, sd_netlink_message **ret);

int sd_netlink_get_events(sd_netlink *nl);
int sd_netlink_get_timeout(sd_netlink *nl, uint64_t *ret);
int sd_netlink_process(sd_netlink *nl, sd_netlink_message **ret);
int sd_netlink_wait(sd_netlink *nl, uint64_t timeout);

int sd_netlink_add_match(sd_netlink *nl, sd_netlink_slot **ret_slot, uint16_t match,
                         sd_netlink_message_handler_t callback,
                         sd_netlink_destroy_t destroy_callback,
                         void *userdata, const char *description);

int sd_netlink_attach_event(sd_netlink *nl, sd_event *e, int64_t priority);
int sd_netlink_detach_event(sd_netlink *nl);
sd_event* sd_netlink_get_event(sd_netlink *nl);
int sd_netlink_attach_filter(sd_netlink *nl, size_t len, const struct sock_filter *filter);

/* Message construction */
int sd_netlink_message_append_string(sd_netlink_message *m, uint16_t attr_type, const char *data);
int sd_netlink_message_append_strv(sd_netlink_message *m, uint16_t attr_type, const char* const *data);
int sd_netlink_message_append_flag(sd_netlink_message *m, uint16_t attr_type);
int sd_netlink_message_append_u8(sd_netlink_message *m, uint16_t attr_type, uint8_t data);
int sd_netlink_message_append_u16(sd_netlink_message *m, uint16_t attr_type, uint16_t data);
int sd_netlink_message_append_u32(sd_netlink_message *m, uint16_t attr_type, uint32_t data);
int sd_netlink_message_append_u64(sd_netlink_message *m, uint16_t attr_type, uint64_t data);
int sd_netlink_message_append_s8(sd_netlink_message *m, uint16_t attr_type, int8_t data);
int sd_netlink_message_append_s16(sd_netlink_message *m, uint16_t attr_type, int16_t data);
int sd_netlink_message_append_s32(sd_netlink_message *m, uint16_t attr_type, int32_t data);
int sd_netlink_message_append_s64(sd_netlink_message *m, uint16_t attr_type, int64_t data);
int sd_netlink_message_append_data(sd_netlink_message *m, uint16_t attr_type, const void *data, size_t len);
int sd_netlink_message_append_container_data(
                sd_netlink_message *m,
                uint16_t container_type,
                uint16_t attr_type,
                const void *data,
                size_t len);
int sd_netlink_message_append_in_addr(sd_netlink_message *m, uint16_t attr_type, const struct in_addr *data);
int sd_netlink_message_append_in6_addr(sd_netlink_message *m, uint16_t attr_type, const struct in6_addr *data);
int sd_netlink_message_append_sockaddr_in(sd_netlink_message *m, uint16_t attr_type, const struct sockaddr_in *data);
int sd_netlink_message_append_sockaddr_in6(sd_netlink_message *m, uint16_t attr_type, const struct sockaddr_in6 *data);
int sd_netlink_message_append_ether_addr(sd_netlink_message *m, uint16_t attr_type, const struct ether_addr *data);
int sd_netlink_message_append_cache_info(sd_netlink_message *m, uint16_t attr_type, const struct ifa_cacheinfo *info);

int sd_netlink_message_open_container(sd_netlink_message *m, uint16_t attr_type);
int sd_netlink_message_open_container_union(sd_netlink_message *m, uint16_t attr_type, const char *key);
int sd_netlink_message_close_container(sd_netlink_message *m);

int sd_netlink_message_open_array(sd_netlink_message *m, uint16_t type);
int sd_netlink_message_cancel_array(sd_netlink_message *m);

/* Reading messages */
int sd_netlink_message_read(sd_netlink_message *m, uint16_t attr_type, size_t size, void *ret);
int sd_netlink_message_read_data(sd_netlink_message *m, uint16_t attr_type, size_t *ret_size, void **ret_data);
int sd_netlink_message_read_string_strdup(sd_netlink_message *m, uint16_t attr_type, char **ret);
int sd_netlink_message_read_string(sd_netlink_message *m, uint16_t attr_type, const char **ret);
int sd_netlink_message_read_strv(sd_netlink_message *m, uint16_t container_type, uint16_t attr_type, char ***ret);
int sd_netlink_message_read_u8(sd_netlink_message *m, uint16_t attr_type, uint8_t *ret);
int sd_netlink_message_read_u16(sd_netlink_message *m, uint16_t attr_type, uint16_t *ret);
int sd_netlink_message_read_u32(sd_netlink_message *m, uint16_t attr_type, uint32_t *ret);
int sd_netlink_message_read_u64(sd_netlink_message *m, uint16_t attr_type, uint64_t *ret);
int sd_netlink_message_read_ether_addr(sd_netlink_message *m, uint16_t attr_type, struct ether_addr *ret);
int sd_netlink_message_read_cache_info(sd_netlink_message *m, uint16_t attr_type, struct ifa_cacheinfo *ret);
int sd_netlink_message_read_in_addr(sd_netlink_message *m, uint16_t attr_type, struct in_addr *ret);
int sd_netlink_message_read_in6_addr(sd_netlink_message *m, uint16_t attr_type, struct in6_addr *ret);
int sd_netlink_message_has_flag(sd_netlink_message *m, uint16_t attr_type);
int sd_netlink_message_enter_container(sd_netlink_message *m, uint16_t attr_type);
int sd_netlink_message_enter_array(sd_netlink_message *m, uint16_t attr_type);
int sd_netlink_message_exit_container(sd_netlink_message *m);

int sd_netlink_message_rewind(sd_netlink_message *m, sd_netlink *nl);

sd_netlink_message* sd_netlink_message_next(sd_netlink_message *m);

sd_netlink_message* sd_netlink_message_ref(sd_netlink_message *m);
sd_netlink_message* sd_netlink_message_unref(sd_netlink_message *m);

int sd_netlink_message_set_request_dump(sd_netlink_message *m, int dump);
int sd_netlink_message_is_error(sd_netlink_message *m);
int sd_netlink_message_get_errno(sd_netlink_message *m);
int sd_netlink_message_get_type(sd_netlink_message *m, uint16_t *ret);
int sd_netlink_message_set_flags(sd_netlink_message *m, uint16_t flags);
int sd_netlink_message_is_broadcast(sd_netlink_message *m);
int sd_netlink_message_get_max_attribute(sd_netlink_message *m, uint16_t *ret);

/* rtnl */
int sd_rtnl_message_get_family(sd_netlink_message *m, int *ret);

int sd_rtnl_message_new_addr(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int ifindex, int family);
int sd_rtnl_message_new_addr_update(sd_netlink *nl, sd_netlink_message **ret, int ifindex, int family);
/* struct ifaddrmsg */
int sd_rtnl_message_addr_get_ifindex(sd_netlink_message *m, int *ret); /* ifa_index */
int sd_rtnl_message_addr_get_family(sd_netlink_message *m, int *ret); /* ifa_family */
int sd_rtnl_message_addr_set_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* ifa_prefixlen */
int sd_rtnl_message_addr_get_prefixlen(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_addr_set_scope(sd_netlink_message *m, uint8_t scope); /* ifa_scope */
int sd_rtnl_message_addr_get_scope(sd_netlink_message *m, uint8_t *ret);

int sd_rtnl_message_new_link(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int ifindex);
/* struct ifinfomsg */
int sd_rtnl_message_link_get_ifindex(sd_netlink_message *m, int *ret); /* ifi_index */
int sd_rtnl_message_link_set_family(sd_netlink_message *m, int family); /* ifi_family */
int sd_rtnl_message_link_get_family(sd_netlink_message *m, int *ret);
int sd_rtnl_message_link_set_type(sd_netlink_message *m, uint16_t type); /* ifi_type */
int sd_rtnl_message_link_get_type(sd_netlink_message *m, uint16_t *ret);
int sd_rtnl_message_link_set_flags(sd_netlink_message *m, uint32_t flags, uint32_t change); /* ifi_flags and ifi_change */
int sd_rtnl_message_link_get_flags(sd_netlink_message *m, uint32_t *ret); /* ifi_flags */

int sd_rtnl_message_new_route(sd_netlink *nl, sd_netlink_message **ret, uint16_t nlmsg_type, int family, uint8_t protocol);
/* struct rtmsg */
int sd_rtnl_message_route_get_family(sd_netlink_message *m, int *ret); /* rtm_family */
int sd_rtnl_message_route_set_dst_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* rtm_dst_len */
int sd_rtnl_message_route_get_dst_prefixlen(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_set_src_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* rtm_src_len */
int sd_rtnl_message_route_get_src_prefixlen(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_set_tos(sd_netlink_message *m, uint8_t tos); /* rtm_tos */
int sd_rtnl_message_route_get_tos(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_set_table(sd_netlink_message *m, uint8_t table); /* rtm_table */
int sd_rtnl_message_route_get_table(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_get_protocol(sd_netlink_message *m, uint8_t *ret); /* rtm_protocol */
int sd_rtnl_message_route_set_scope(sd_netlink_message *m, uint8_t scope); /* rtm_scope */
int sd_rtnl_message_route_get_scope(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_set_type(sd_netlink_message *m, uint8_t type); /* rtm_type */
int sd_rtnl_message_route_get_type(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_route_set_flags(sd_netlink_message *m, uint32_t flags); /* rtm_flags */
int sd_rtnl_message_route_get_flags(sd_netlink_message *m, uint32_t *ret);

int sd_rtnl_message_new_nexthop(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int family, uint8_t protocol);
/* struct nhmsg */
int sd_rtnl_message_nexthop_get_family(sd_netlink_message *m, int *ret); /* nh_family */
int sd_rtnl_message_nexthop_set_flags(sd_netlink_message *m, uint32_t flags); /* nh_flags, RTNH_F flags */
int sd_rtnl_message_nexthop_get_flags(sd_netlink_message *m, uint32_t *ret);
int sd_rtnl_message_nexthop_get_protocol(sd_netlink_message *m, uint8_t *ret); /* nh_protocol */

int sd_rtnl_message_new_neigh(sd_netlink *nl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex, int family);
/* struct ndmsg */
int sd_rtnl_message_neigh_get_ifindex(sd_netlink_message *m, int *ret); /* ndm_ifindex */
int sd_rtnl_message_neigh_get_family(sd_netlink_message *m, int *ret); /* ndm_family */
int sd_rtnl_message_neigh_set_state(sd_netlink_message *m, uint16_t state); /* ndm_state */
int sd_rtnl_message_neigh_get_state(sd_netlink_message *m, uint16_t *ret);
int sd_rtnl_message_neigh_set_flags(sd_netlink_message *m, uint8_t flags); /* ndm_flags */
int sd_rtnl_message_neigh_get_flags(sd_netlink_message *m, uint8_t *ret);

int sd_rtnl_message_new_addrlabel(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex, int family);
/* struct ifaddrlblmsg */
int sd_rtnl_message_addrlabel_set_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* ifal_prefixlen */
int sd_rtnl_message_addrlabel_get_prefixlen(sd_netlink_message *m, uint8_t *ret);

int sd_rtnl_message_new_routing_policy_rule(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int family);
/* struct fib_rule_hdr */
int sd_rtnl_message_routing_policy_rule_get_family(sd_netlink_message *m, int *ret); /* family */
int sd_rtnl_message_routing_policy_rule_set_dst_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* dst_len */
int sd_rtnl_message_routing_policy_rule_get_dst_prefixlen(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_routing_policy_rule_set_src_prefixlen(sd_netlink_message *m, uint8_t prefixlen); /* src_len */
int sd_rtnl_message_routing_policy_rule_get_src_prefixlen(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_routing_policy_rule_set_tos(sd_netlink_message *m, uint8_t tos); /* tos */
int sd_rtnl_message_routing_policy_rule_get_tos(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_routing_policy_rule_set_table(sd_netlink_message *m, uint8_t table); /* table */
int sd_rtnl_message_routing_policy_rule_get_table(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_routing_policy_rule_set_action(sd_netlink_message *m, uint8_t action); /* action */
int sd_rtnl_message_routing_policy_rule_get_action(sd_netlink_message *m, uint8_t *ret);
int sd_rtnl_message_routing_policy_rule_set_flags(sd_netlink_message *m, uint32_t flags); /* flags */
int sd_rtnl_message_routing_policy_rule_get_flags(sd_netlink_message *m, uint32_t *ret);

int sd_rtnl_message_new_traffic_control(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type,
                                        int ifindex, uint32_t handle, uint32_t parent);
/* struct tcmsg */
int sd_rtnl_message_traffic_control_get_ifindex(sd_netlink_message *m, int *ret); /* tcm_ifindex */
int sd_rtnl_message_traffic_control_get_handle(sd_netlink_message *m, uint32_t *ret); /* tcm_handle */
int sd_rtnl_message_traffic_control_get_parent(sd_netlink_message *m, uint32_t *ret); /* tcm_parent */

int sd_rtnl_message_new_mdb(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex);

int sd_rtnl_message_new_nsid(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type);

/* genl */
int sd_genl_socket_open(sd_netlink **ret);
int sd_genl_message_new(sd_netlink *genl, const char *family_name, uint8_t cmd, sd_netlink_message **ret);
int sd_genl_message_get_family_name(sd_netlink *genl, sd_netlink_message *m, const char **ret);
int sd_genl_message_get_command(sd_netlink *genl, sd_netlink_message *m, uint8_t *ret);
int sd_genl_add_match(sd_netlink *nl, sd_netlink_slot **ret_slot, const char *family_name,
                      const char *multicast_group_name, uint8_t command,
                      sd_netlink_message_handler_t callback,
                      sd_netlink_destroy_t destroy_callback,
                      void *userdata, const char *description);

/* slot */
sd_netlink_slot *sd_netlink_slot_ref(sd_netlink_slot *slot);
sd_netlink_slot *sd_netlink_slot_unref(sd_netlink_slot *slot);

sd_netlink* sd_netlink_slot_get_netlink(sd_netlink_slot *slot);
void* sd_netlink_slot_get_userdata(sd_netlink_slot *slot);
void* sd_netlink_slot_set_userdata(sd_netlink_slot *slot, void *userdata);
int sd_netlink_slot_get_destroy_callback(sd_netlink_slot *slot, sd_netlink_destroy_t *ret);
int sd_netlink_slot_set_destroy_callback(sd_netlink_slot *slot, sd_netlink_destroy_t callback);
int sd_netlink_slot_get_floating(sd_netlink_slot *slot);
int sd_netlink_slot_set_floating(sd_netlink_slot *slot, int b);
int sd_netlink_slot_get_description(sd_netlink_slot *slot, const char **ret);
int sd_netlink_slot_set_description(sd_netlink_slot *slot, const char *description);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink, sd_netlink_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink_message, sd_netlink_message_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink_slot, sd_netlink_slot_unref);

_SD_END_DECLARATIONS;

#endif
