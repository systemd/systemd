/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdrtnlhfoo
#define foosdrtnlhfoo

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

#include "sd-event.h"
#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_rtnl sd_rtnl;
typedef struct sd_rtnl_message sd_rtnl_message;

/* callback */

typedef int (*sd_rtnl_message_handler_t)(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata);

/* bus */
int sd_rtnl_open(sd_rtnl **nl, unsigned n_groups, ...);

sd_rtnl *sd_rtnl_ref(sd_rtnl *nl);
sd_rtnl *sd_rtnl_unref(sd_rtnl *nl);

int sd_rtnl_send(sd_rtnl *nl, sd_rtnl_message *message, uint32_t *serial);
int sd_rtnl_call_async(sd_rtnl *nl, sd_rtnl_message *message,
                       sd_rtnl_message_handler_t callback,
                       void *userdata, uint64_t usec, uint32_t *serial);
int sd_rtnl_call_async_cancel(sd_rtnl *nl, uint32_t serial);
int sd_rtnl_call(sd_rtnl *nl, sd_rtnl_message *message, uint64_t timeout,
                 sd_rtnl_message **reply);


int sd_rtnl_get_events(sd_rtnl *nl);
int sd_rtnl_get_timeout(sd_rtnl *nl, uint64_t *timeout);
int sd_rtnl_process(sd_rtnl *nl, sd_rtnl_message **ret);
int sd_rtnl_wait(sd_rtnl *nl, uint64_t timeout);
int sd_rtnl_flush(sd_rtnl *nl);

int sd_rtnl_add_match(sd_rtnl *nl, uint16_t match, sd_rtnl_message_handler_t c, void *userdata);
int sd_rtnl_remove_match(sd_rtnl *nl, uint16_t match, sd_rtnl_message_handler_t c, void *userdata);

int sd_rtnl_attach_event(sd_rtnl *nl, sd_event *e, int priority);
int sd_rtnl_detach_event(sd_rtnl *nl);

/* messages */
int sd_rtnl_message_new_link(sd_rtnl *rtnl, sd_rtnl_message **ret, uint16_t msg_type, int index);
int sd_rtnl_message_new_addr_update(sd_rtnl *rtnl, sd_rtnl_message **ret, int index, unsigned char family);
int sd_rtnl_message_new_addr(sd_rtnl *rtnl, sd_rtnl_message **ret, uint16_t msg_type, int index,
                             unsigned char family);
int sd_rtnl_message_new_route(sd_rtnl *rtnl, sd_rtnl_message **ret, uint16_t nlmsg_type,
                              unsigned char rtm_family);

sd_rtnl_message *sd_rtnl_message_ref(sd_rtnl_message *m);
sd_rtnl_message *sd_rtnl_message_unref(sd_rtnl_message *m);

int sd_rtnl_message_request_dump(sd_rtnl_message *m, int dump);
int sd_rtnl_message_get_errno(sd_rtnl_message *m);
int sd_rtnl_message_get_type(sd_rtnl_message *m, uint16_t *type);
int sd_rtnl_message_is_broadcast(sd_rtnl_message *m);

int sd_rtnl_message_addr_set_prefixlen(sd_rtnl_message *m, unsigned char prefixlen);
int sd_rtnl_message_addr_set_scope(sd_rtnl_message *m, unsigned char scope);
int sd_rtnl_message_addr_set_flags(sd_rtnl_message *m, unsigned char flags);
int sd_rtnl_message_addr_get_family(sd_rtnl_message *m, unsigned char *family);
int sd_rtnl_message_addr_get_prefixlen(sd_rtnl_message *m, unsigned char *prefixlen);
int sd_rtnl_message_addr_get_scope(sd_rtnl_message *m, unsigned char *scope);
int sd_rtnl_message_addr_get_flags(sd_rtnl_message *m, unsigned char *flags);
int sd_rtnl_message_addr_get_ifindex(sd_rtnl_message *m, int *ifindex);

int sd_rtnl_message_link_set_flags(sd_rtnl_message *m, unsigned flags, unsigned change);
int sd_rtnl_message_link_set_type(sd_rtnl_message *m, unsigned type);
int sd_rtnl_message_link_get_ifindex(sd_rtnl_message *m, int *ifindex);
int sd_rtnl_message_link_get_flags(sd_rtnl_message *m, unsigned *flags);

int sd_rtnl_message_route_set_dst_prefixlen(sd_rtnl_message *m, unsigned char prefixlen);
int sd_rtnl_message_route_set_scope(sd_rtnl_message *m, unsigned char scope);

int sd_rtnl_message_append_string(sd_rtnl_message *m, unsigned short type, const char *data);
int sd_rtnl_message_append_u8(sd_rtnl_message *m, unsigned short type, uint8_t data);
int sd_rtnl_message_append_u16(sd_rtnl_message *m, unsigned short type, uint16_t data);
int sd_rtnl_message_append_u32(sd_rtnl_message *m, unsigned short type, uint32_t data);
int sd_rtnl_message_append_in_addr(sd_rtnl_message *m, unsigned short type, const struct in_addr *data);
int sd_rtnl_message_append_in6_addr(sd_rtnl_message *m, unsigned short type, const struct in6_addr *data);
int sd_rtnl_message_append_ether_addr(sd_rtnl_message *m, unsigned short type, const struct ether_addr *data);
int sd_rtnl_message_append_cache_info(sd_rtnl_message *m, unsigned short type, const struct ifa_cacheinfo *info);

int sd_rtnl_message_open_container(sd_rtnl_message *m, unsigned short type);
int sd_rtnl_message_open_container_union(sd_rtnl_message *m, unsigned short type, const char *key);
int sd_rtnl_message_close_container(sd_rtnl_message *m);

int sd_rtnl_message_read_string(sd_rtnl_message *m, unsigned short type, char **data);
int sd_rtnl_message_read_u8(sd_rtnl_message *m, unsigned short type, uint8_t *data);
int sd_rtnl_message_read_u16(sd_rtnl_message *m, unsigned short type, uint16_t *data);
int sd_rtnl_message_read_u32(sd_rtnl_message *m, unsigned short type, uint32_t *data);
int sd_rtnl_message_read_ether_addr(sd_rtnl_message *m, unsigned short type, struct ether_addr *data);
int sd_rtnl_message_read_cache_info(sd_rtnl_message *m, unsigned short type, struct ifa_cacheinfo *info);
int sd_rtnl_message_read_in_addr(sd_rtnl_message *m, unsigned short type, struct in_addr *data);
int sd_rtnl_message_read_in6_addr(sd_rtnl_message *m, unsigned short type, struct in6_addr *data);
int sd_rtnl_message_enter_container(sd_rtnl_message *m, unsigned short type);
int sd_rtnl_message_exit_container(sd_rtnl_message *m);

int sd_rtnl_message_rewind(sd_rtnl_message *m);

sd_rtnl_message *sd_rtnl_message_next(sd_rtnl_message *m);

_SD_END_DECLARATIONS;

#endif
