/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdnetlinkhfoo
#define foosdnetlinkhfoo

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#include "sd-event.h"
#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;

/* callback */

typedef int (*sd_netlink_message_handler_t)(sd_netlink *nl, sd_netlink_message *m, void *userdata);

/* bus */
int sd_netlink_new_from_netlink(sd_netlink **nl, int fd);
int sd_netlink_open(sd_netlink **nl);
int sd_netlink_open_fd(sd_netlink **nl, int fd);
int sd_netlink_inc_rcvbuf(const sd_netlink *const rtnl, const int size);

sd_netlink *sd_netlink_ref(sd_netlink *nl);
sd_netlink *sd_netlink_unref(sd_netlink *nl);

int sd_netlink_send(sd_netlink *nl, sd_netlink_message *message, uint32_t *serial);
int sd_netlink_call_async(sd_netlink *nl, sd_netlink_message *message,
                       sd_netlink_message_handler_t callback,
                       void *userdata, uint64_t usec, uint32_t *serial);
int sd_netlink_call_async_cancel(sd_netlink *nl, uint32_t serial);
int sd_netlink_call(sd_netlink *nl, sd_netlink_message *message, uint64_t timeout,
                 sd_netlink_message **reply);

int sd_netlink_get_events(sd_netlink *nl);
int sd_netlink_get_timeout(sd_netlink *nl, uint64_t *timeout);
int sd_netlink_process(sd_netlink *nl, sd_netlink_message **ret);
int sd_netlink_wait(sd_netlink *nl, uint64_t timeout);

int sd_netlink_add_match(sd_netlink *nl, uint16_t match, sd_netlink_message_handler_t c, void *userdata);
int sd_netlink_remove_match(sd_netlink *nl, uint16_t match, sd_netlink_message_handler_t c, void *userdata);

int sd_netlink_attach_event(sd_netlink *nl, sd_event *e, int priority);
int sd_netlink_detach_event(sd_netlink *nl);

int sd_netlink_message_append_string(sd_netlink_message *m, unsigned short type, const char *data);
int sd_netlink_message_append_flag(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_append_u8(sd_netlink_message *m, unsigned short type, uint8_t data);
int sd_netlink_message_append_u16(sd_netlink_message *m, unsigned short type, uint16_t data);
int sd_netlink_message_append_u32(sd_netlink_message *m, unsigned short type, uint32_t data);
int sd_netlink_message_append_in_addr(sd_netlink_message *m, unsigned short type, const struct in_addr *data);
int sd_netlink_message_append_in6_addr(sd_netlink_message *m, unsigned short type, const struct in6_addr *data);
int sd_netlink_message_append_ether_addr(sd_netlink_message *m, unsigned short type, const struct ether_addr *data);
int sd_netlink_message_append_cache_info(sd_netlink_message *m, unsigned short type, const struct ifa_cacheinfo *info);

int sd_netlink_message_open_container(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_open_container_union(sd_netlink_message *m, unsigned short type, const char *key);
int sd_netlink_message_close_container(sd_netlink_message *m);

int sd_netlink_message_read_string(sd_netlink_message *m, unsigned short type, const char **data);
int sd_netlink_message_read_u8(sd_netlink_message *m, unsigned short type, uint8_t *data);
int sd_netlink_message_read_u16(sd_netlink_message *m, unsigned short type, uint16_t *data);
int sd_netlink_message_read_u32(sd_netlink_message *m, unsigned short type, uint32_t *data);
int sd_netlink_message_read_ether_addr(sd_netlink_message *m, unsigned short type, struct ether_addr *data);
int sd_netlink_message_read_cache_info(sd_netlink_message *m, unsigned short type, struct ifa_cacheinfo *info);
int sd_netlink_message_read_in_addr(sd_netlink_message *m, unsigned short type, struct in_addr *data);
int sd_netlink_message_read_in6_addr(sd_netlink_message *m, unsigned short type, struct in6_addr *data);
int sd_netlink_message_enter_container(sd_netlink_message *m, unsigned short type);
int sd_netlink_message_exit_container(sd_netlink_message *m);

int sd_netlink_message_rewind(sd_netlink_message *m);

sd_netlink_message *sd_netlink_message_next(sd_netlink_message *m);

sd_netlink_message *sd_netlink_message_ref(sd_netlink_message *m);
sd_netlink_message *sd_netlink_message_unref(sd_netlink_message *m);

int sd_netlink_message_request_dump(sd_netlink_message *m, int dump);
int sd_netlink_message_is_error(sd_netlink_message *m);
int sd_netlink_message_get_errno(sd_netlink_message *m);
int sd_netlink_message_get_type(sd_netlink_message *m, uint16_t *type);
int sd_netlink_message_set_flags(sd_netlink_message *m, uint16_t flags);
int sd_netlink_message_is_broadcast(sd_netlink_message *m);

/* rtnl */

int sd_rtnl_message_new_link(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index);
int sd_rtnl_message_new_addr_update(sd_netlink *nl, sd_netlink_message **ret, int index, int family);
int sd_rtnl_message_new_addr(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index, int family);
int sd_rtnl_message_new_route(sd_netlink *nl, sd_netlink_message **ret, uint16_t nlmsg_type, int rtm_family, unsigned char rtm_protocol);
int sd_rtnl_message_new_neigh(sd_netlink *nl, sd_netlink_message **ret, uint16_t msg_type, int index, int nda_family);

int sd_rtnl_message_get_family(sd_netlink_message *m, int *family);

int sd_rtnl_message_addr_set_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_addr_set_scope(sd_netlink_message *m, unsigned char scope);
int sd_rtnl_message_addr_set_flags(sd_netlink_message *m, unsigned char flags);
int sd_rtnl_message_addr_get_family(sd_netlink_message *m, int *family);
int sd_rtnl_message_addr_get_prefixlen(sd_netlink_message *m, unsigned char *prefixlen);
int sd_rtnl_message_addr_get_scope(sd_netlink_message *m, unsigned char *scope);
int sd_rtnl_message_addr_get_flags(sd_netlink_message *m, unsigned char *flags);
int sd_rtnl_message_addr_get_ifindex(sd_netlink_message *m, int *ifindex);

int sd_rtnl_message_link_set_flags(sd_netlink_message *m, unsigned flags, unsigned change);
int sd_rtnl_message_link_set_type(sd_netlink_message *m, unsigned type);
int sd_rtnl_message_link_set_family(sd_netlink_message *m, unsigned family);
int sd_rtnl_message_link_get_ifindex(sd_netlink_message *m, int *ifindex);
int sd_rtnl_message_link_get_flags(sd_netlink_message *m, unsigned *flags);
int sd_rtnl_message_link_get_type(sd_netlink_message *m, unsigned *type);

int sd_rtnl_message_route_set_dst_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_route_set_src_prefixlen(sd_netlink_message *m, unsigned char prefixlen);
int sd_rtnl_message_route_set_scope(sd_netlink_message *m, unsigned char scope);
int sd_rtnl_message_route_get_family(sd_netlink_message *m, int *family);
int sd_rtnl_message_route_get_dst_prefixlen(sd_netlink_message *m, unsigned char *dst_len);
int sd_rtnl_message_route_get_src_prefixlen(sd_netlink_message *m, unsigned char *src_len);

int sd_rtnl_message_neigh_set_flags(sd_netlink_message *m, uint8_t flags);
int sd_rtnl_message_neigh_set_state(sd_netlink_message *m, uint16_t state);
int sd_rtnl_message_neigh_get_family(sd_netlink_message *m, int *family);
int sd_rtnl_message_neigh_get_ifindex(sd_netlink_message *m, int *family);
int sd_rtnl_message_neigh_get_state(sd_netlink_message *m, uint16_t *state);
int sd_rtnl_message_neigh_get_flags(sd_netlink_message *m, uint8_t *flags);

_SD_END_DECLARATIONS;

#endif
