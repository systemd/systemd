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
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include "sd-event.h"

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_netlink sd_netlink;
typedef struct sd_genl_socket sd_genl_socket;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;

typedef enum sd_genl_family_t {
        SD_GENL_ERROR,
        SD_GENL_DONE,
        SD_GENL_ID_CTRL,
        SD_GENL_WIREGUARD,
        SD_GENL_FOU,
        SD_GENL_L2TP,
        SD_GENL_MACSEC,
        SD_GENL_NL80211,
        SD_GENL_BATADV,
        _SD_GENL_FAMILY_MAX,
        _SD_GENL_FAMILY_INVALID = -EINVAL,
        _SD_ENUM_FORCE_S64(GENL_FAMILY)
} sd_genl_family_t;

/* callback */

typedef int (*sd_netlink_message_handler_t)(sd_netlink *nl, sd_netlink_message *m, void *userdata);
typedef _sd_destroy_t sd_netlink_destroy_t;

/* bus */
int sd_netlink_new_from_netlink(sd_netlink **nl, int fd);
int sd_netlink_open(sd_netlink **nl);
int sd_netlink_open_fd(sd_netlink **nl, int fd);
int sd_netlink_inc_rcvbuf(sd_netlink *nl, const size_t size);

sd_netlink *sd_netlink_ref(sd_netlink *nl);
sd_netlink *sd_netlink_unref(sd_netlink *nl);

int sd_netlink_send(sd_netlink *nl, sd_netlink_message *message, uint32_t *serial);
int sd_netlink_sendv(sd_netlink *nl, sd_netlink_message **messages, size_t msgcnt, uint32_t **ret_serial);
int sd_netlink_call_async(sd_netlink *nl, sd_netlink_slot **ret_slot, sd_netlink_message *message,
                          sd_netlink_message_handler_t callback, sd_netlink_destroy_t destoy_callback,
                          void *userdata, uint64_t usec, const char *description);
int sd_netlink_call(sd_netlink *nl, sd_netlink_message *message, uint64_t timeout,
                    sd_netlink_message **reply);
int sd_netlink_read(sd_netlink *nl, uint32_t serial, uint64_t timeout, sd_netlink_message **reply);

int sd_netlink_get_events(const sd_netlink *nl);
int sd_netlink_get_timeout(const sd_netlink *nl, uint64_t *timeout);
int sd_netlink_process(sd_netlink *nl, sd_netlink_message **ret);
int sd_netlink_wait(sd_netlink *nl, uint64_t timeout);

int sd_netlink_add_match(sd_netlink *nl, sd_netlink_slot **ret_slot, uint16_t match,
                         sd_netlink_message_handler_t callback,
                         sd_netlink_destroy_t destroy_callback,
                         void *userdata, const char *description);

int sd_netlink_attach_event(sd_netlink *nl, sd_event *e, int64_t priority);
int sd_netlink_detach_event(sd_netlink *nl);

int sd_netlink_message_append_string(sd_netlink_message *m, unsigned short type, const char *data);
int sd_netlink_message_append_strv(sd_netlink_message *m, unsigned short type, char * const *data);
int sd_netlink_message_append_flag(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_append_u8(sd_netlink_message *m, unsigned short type, uint8_t data);
int sd_netlink_message_append_u16(sd_netlink_message *m, unsigned short type, uint16_t data);
int sd_netlink_message_append_u32(sd_netlink_message *m, unsigned short type, uint32_t data);
int sd_netlink_message_append_u64(sd_netlink_message *m, unsigned short type, uint64_t data);
int sd_netlink_message_append_s8(sd_netlink_message *m, unsigned short type, int8_t data);
int sd_netlink_message_append_s16(sd_netlink_message *m, unsigned short type, int16_t data);
int sd_netlink_message_append_s32(sd_netlink_message *m, unsigned short type, int32_t data);
int sd_netlink_message_append_s64(sd_netlink_message *m, unsigned short type, int64_t data);
int sd_netlink_message_append_data(sd_netlink_message *m, unsigned short type, const void *data, size_t len);
int sd_netlink_message_append_in_addr(sd_netlink_message *m, unsigned short type, const struct in_addr *data);
int sd_netlink_message_append_in6_addr(sd_netlink_message *m, unsigned short type, const struct in6_addr *data);
int sd_netlink_message_append_sockaddr_in(sd_netlink_message *m, unsigned short type, const struct sockaddr_in *data);
int sd_netlink_message_append_sockaddr_in6(sd_netlink_message *m, unsigned short type, const struct sockaddr_in6 *data);
int sd_netlink_message_append_ether_addr(sd_netlink_message *m, unsigned short type, const struct ether_addr *data);
int sd_netlink_message_append_cache_info(sd_netlink_message *m, unsigned short type, const struct ifa_cacheinfo *info);

int sd_netlink_message_open_container(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_open_container_union(sd_netlink_message *m, unsigned short type, const char *key);
int sd_netlink_message_close_container(sd_netlink_message *m);

int sd_netlink_message_read(sd_netlink_message *m, unsigned short type, size_t size, void *data);
int sd_netlink_message_read_data(sd_netlink_message *m, unsigned short type, size_t *ret_size, void **ret_data);
int sd_netlink_message_read_string_strdup(sd_netlink_message *m, unsigned short type, char **data);
int sd_netlink_message_read_string(sd_netlink_message *m, unsigned short type, const char **data);
int sd_netlink_message_read_strv(sd_netlink_message *m, unsigned short container_type, unsigned short type_id, char ***ret);
int sd_netlink_message_read_u8(sd_netlink_message *m, unsigned short type, uint8_t *data);
int sd_netlink_message_read_u16(sd_netlink_message *m, unsigned short type, uint16_t *data);
int sd_netlink_message_read_u32(sd_netlink_message *m, unsigned short type, uint32_t *data);
int sd_netlink_message_read_ether_addr(sd_netlink_message *m, unsigned short type, struct ether_addr *data);
int sd_netlink_message_read_cache_info(sd_netlink_message *m, unsigned short type, struct ifa_cacheinfo *info);
int sd_netlink_message_read_in_addr(sd_netlink_message *m, unsigned short type, struct in_addr *data);
int sd_netlink_message_read_in6_addr(sd_netlink_message *m, unsigned short type, struct in6_addr *data);
int sd_netlink_message_has_flag(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_enter_container(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_enter_array(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_exit_container(sd_netlink_message *m);

int sd_netlink_message_open_array(sd_netlink_message *m, uint16_t type);
int sd_netlink_message_cancel_array(sd_netlink_message *m);

int sd_netlink_message_rewind(sd_netlink_message *m, sd_netlink *genl);

sd_netlink_message *sd_netlink_message_next(sd_netlink_message *m);

sd_netlink_message *sd_netlink_message_ref(sd_netlink_message *m);
sd_netlink_message *sd_netlink_message_unref(sd_netlink_message *m);

int sd_netlink_message_request_dump(sd_netlink_message *m, int dump);
int sd_netlink_message_is_error(const sd_netlink_message *m);
int sd_netlink_message_get_errno(const sd_netlink_message *m);
int sd_netlink_message_get_type(const sd_netlink_message *m, uint16_t *type);
int sd_netlink_message_set_flags(sd_netlink_message *m, uint16_t flags);
int sd_netlink_message_is_broadcast(const sd_netlink_message *m);

/* rtnl */
int sd_rtnl_message_get_family(const sd_netlink_message *m, int *family);

int sd_rtnl_message_new_addr(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index, int family);
int sd_rtnl_message_new_addr_update(sd_netlink *nl, sd_netlink_message **ret, int index, int family);
int sd_rtnl_message_addr_set_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_addr_set_scope(sd_netlink_message *m, unsigned char scope);
int sd_rtnl_message_addr_set_flags(sd_netlink_message *m, unsigned char flags);
int sd_rtnl_message_addr_get_family(const sd_netlink_message *m, int *family);
int sd_rtnl_message_addr_get_prefixlen(const sd_netlink_message *m, unsigned char *prefixlen);
int sd_rtnl_message_addr_get_scope(const sd_netlink_message *m, unsigned char *scope);
int sd_rtnl_message_addr_get_flags(const sd_netlink_message *m, unsigned char *flags);
int sd_rtnl_message_addr_get_ifindex(const sd_netlink_message *m, int *ifindex);

int sd_rtnl_message_new_link(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index);
int sd_rtnl_message_link_set_flags(sd_netlink_message *m, unsigned flags, unsigned change);
int sd_rtnl_message_link_set_type(sd_netlink_message *m, unsigned type);
int sd_rtnl_message_link_set_family(sd_netlink_message *m, unsigned family);
int sd_rtnl_message_link_get_ifindex(const sd_netlink_message *m, int *ifindex);
int sd_rtnl_message_link_get_flags(const sd_netlink_message *m, unsigned *flags);
int sd_rtnl_message_link_get_type(const sd_netlink_message *m, unsigned short *type);

int sd_rtnl_message_new_route(sd_netlink *nl, sd_netlink_message **ret, uint16_t nlmsg_type, int rtm_family, unsigned char rtm_protocol);
int sd_rtnl_message_route_set_dst_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_route_set_src_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_route_set_scope(sd_netlink_message *m, unsigned char scope);
int sd_rtnl_message_route_set_flags(sd_netlink_message *m, unsigned flags);
int sd_rtnl_message_route_set_table(sd_netlink_message *m, unsigned char table);
int sd_rtnl_message_route_set_type(sd_netlink_message *m, unsigned char type);
int sd_rtnl_message_route_get_flags(const sd_netlink_message *m, unsigned *flags);
int sd_rtnl_message_route_get_family(const sd_netlink_message *m, int *family);
int sd_rtnl_message_route_get_protocol(const sd_netlink_message *m, unsigned char *protocol);
int sd_rtnl_message_route_get_scope(const sd_netlink_message *m, unsigned char *scope);
int sd_rtnl_message_route_get_tos(const sd_netlink_message *m, unsigned char *tos);
int sd_rtnl_message_route_get_table(const sd_netlink_message *m, unsigned char *table);
int sd_rtnl_message_route_get_dst_prefixlen(const sd_netlink_message *m, unsigned char *dst_len);
int sd_rtnl_message_route_get_src_prefixlen(const sd_netlink_message *m, unsigned char *src_len);
int sd_rtnl_message_route_get_type(const sd_netlink_message *m, unsigned char *type);

int sd_rtnl_message_new_nexthop(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nhmsg_type, int nh_family, unsigned char nh_protocol);
int sd_rtnl_message_nexthop_set_flags(sd_netlink_message *m, uint8_t flags);
int sd_rtnl_message_nexthop_get_family(const sd_netlink_message *m, uint8_t *family);
int sd_rtnl_message_nexthop_get_protocol(const sd_netlink_message *m, uint8_t *protocol);

int sd_rtnl_message_new_neigh(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index, int nda_family);
int sd_rtnl_message_neigh_set_flags(sd_netlink_message *m, uint8_t flags);
int sd_rtnl_message_neigh_set_state(sd_netlink_message *m, uint16_t state);
int sd_rtnl_message_neigh_get_family(const sd_netlink_message *m, int *family);
int sd_rtnl_message_neigh_get_ifindex(const sd_netlink_message *m, int *index);
int sd_rtnl_message_neigh_get_state(const sd_netlink_message *m, uint16_t *state);
int sd_rtnl_message_neigh_get_flags(const sd_netlink_message *m, uint8_t *flags);

int sd_rtnl_message_new_addrlabel(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifindex, int ifal_family);
int sd_rtnl_message_addrlabel_set_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_addrlabel_get_prefixlen(const sd_netlink_message *m, unsigned char *prefixlen);

int sd_rtnl_message_new_routing_policy_rule(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int ifal_family);
int sd_rtnl_message_routing_policy_rule_set_tos(sd_netlink_message *m, uint8_t tos);
int sd_rtnl_message_routing_policy_rule_get_tos(const sd_netlink_message *m, uint8_t *tos);
int sd_rtnl_message_routing_policy_rule_set_table(sd_netlink_message *m, uint8_t table);
int sd_rtnl_message_routing_policy_rule_get_table(const sd_netlink_message *m, uint8_t *table);
int sd_rtnl_message_routing_policy_rule_set_fib_src_prefixlen(sd_netlink_message *m, uint8_t len);
int sd_rtnl_message_routing_policy_rule_get_fib_src_prefixlen(const sd_netlink_message *m, uint8_t *len);
int sd_rtnl_message_routing_policy_rule_set_fib_dst_prefixlen(sd_netlink_message *m, uint8_t len);
int sd_rtnl_message_routing_policy_rule_get_fib_dst_prefixlen(const sd_netlink_message *m, uint8_t *len);
int sd_rtnl_message_routing_policy_rule_set_fib_type(sd_netlink_message *m, uint8_t type);
int sd_rtnl_message_routing_policy_rule_get_fib_type(const sd_netlink_message *m, uint8_t *type);
int sd_rtnl_message_routing_policy_rule_set_flags(sd_netlink_message *m, uint32_t flags);
int sd_rtnl_message_routing_policy_rule_get_flags(const sd_netlink_message *m, uint32_t *flags);

int sd_rtnl_message_new_qdisc(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int tcm_family, int tcm_ifindex);
int sd_rtnl_message_set_qdisc_parent(sd_netlink_message *m, uint32_t parent);
int sd_rtnl_message_set_qdisc_handle(sd_netlink_message *m, uint32_t handle);

int sd_rtnl_message_new_tclass(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int tcm_family, int tcm_ifindex);
int sd_rtnl_message_set_tclass_parent(sd_netlink_message *m, uint32_t parent);
int sd_rtnl_message_set_tclass_handle(sd_netlink_message *m, uint32_t handle);

int sd_rtnl_message_new_mdb(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t nlmsg_type, int mdb_ifindex);

/* nfnl */
int sd_nfnl_socket_open(sd_netlink **nl);
int sd_nfnl_message_batch_begin(sd_netlink *nfnl, sd_netlink_message **ret);
int sd_nfnl_message_batch_end(sd_netlink *nfnl, sd_netlink_message **ret);
int sd_nfnl_nft_message_del_table(sd_netlink *nfnl, sd_netlink_message **ret,
                                  int family, const char *table);
int sd_nfnl_nft_message_new_table(sd_netlink *nfnl, sd_netlink_message **ret,
                                  int family, const char *table, uint16_t nl_flags);
int sd_nfnl_nft_message_new_basechain(sd_netlink *nfnl, sd_netlink_message **ret,
                                      int family, const char *table, const char *chain,
                                      const char *type, uint8_t hook, int prio);
int sd_nfnl_nft_message_new_rule(sd_netlink *nfnl, sd_netlink_message **ret,
                                 int family, const char *table, const char *chain);
int sd_nfnl_nft_message_new_set(sd_netlink *nfnl, sd_netlink_message **ret,
                                int family, const char *table, const char *set_name,
                                uint32_t setid, uint32_t klen);
int sd_nfnl_nft_message_new_setelems_begin(sd_netlink *nfnl, sd_netlink_message **ret,
                                           int family, const char *table, const char *set_name);
int sd_nfnl_nft_message_del_setelems_begin(sd_netlink *nfnl, sd_netlink_message **ret,
                                           int family, const char *table, const char *set_name);
int sd_nfnl_nft_message_add_setelem(sd_netlink_message *m,
                                    uint32_t num,
                                    const void *key, uint32_t klen,
                                    const void *data, uint32_t dlen);
int sd_nfnl_nft_message_add_setelem_end(sd_netlink_message *m);

/* genl */
int sd_genl_socket_open(sd_netlink **nl);
int sd_genl_message_new(sd_netlink *nl, sd_genl_family_t family, uint8_t cmd, sd_netlink_message **m);
int sd_genl_message_get_family(const sd_netlink *nl, const sd_netlink_message *m, sd_genl_family_t *family);

/* slot */
sd_netlink_slot *sd_netlink_slot_ref(sd_netlink_slot *nl);
sd_netlink_slot *sd_netlink_slot_unref(sd_netlink_slot *nl);

sd_netlink *sd_netlink_slot_get_netlink(sd_netlink_slot *slot);
void *sd_netlink_slot_get_userdata(sd_netlink_slot *slot);
void *sd_netlink_slot_set_userdata(sd_netlink_slot *slot, void *userdata);
int sd_netlink_slot_get_destroy_callback(const sd_netlink_slot *slot, sd_netlink_destroy_t *callback);
int sd_netlink_slot_set_destroy_callback(sd_netlink_slot *slot, sd_netlink_destroy_t callback);
int sd_netlink_slot_get_floating(const sd_netlink_slot *slot);
int sd_netlink_slot_set_floating(sd_netlink_slot *slot, int b);
int sd_netlink_slot_get_description(const sd_netlink_slot *slot, const char **description);
int sd_netlink_slot_set_description(sd_netlink_slot *slot, const char *description);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink, sd_netlink_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink_message, sd_netlink_message_unref);
_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_netlink_slot, sd_netlink_slot_unref);

_SD_END_DECLARATIONS;

#endif
