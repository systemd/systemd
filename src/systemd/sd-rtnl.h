/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#pragma once

#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <util.h>

typedef struct sd_rtnl sd_rtnl;
typedef struct sd_rtnl_message sd_rtnl_message;

/* bus */
int sd_rtnl_open(uint32_t groups, sd_rtnl **nl);

sd_rtnl *sd_rtnl_ref(sd_rtnl *nl);
sd_rtnl *sd_rtnl_unref(sd_rtnl *nl);

int sd_rtnl_send_with_reply_and_block(sd_rtnl *nl, sd_rtnl_message *message, uint64_t timeout, sd_rtnl_message **reply);

/* messages */
int sd_rtnl_message_link_new(uint16_t msg_type, int index, unsigned int type,
                             unsigned int flags, sd_rtnl_message **ret);
int sd_rtnl_message_addr_new(uint16_t msg_type, int index, unsigned char family,
                             unsigned char prefixlen, unsigned char flags,
                             unsigned char scope, sd_rtnl_message **ret);
int sd_rtnl_message_route_new(uint16_t nlmsg_type, unsigned char rtm_family,
                              unsigned char rtm_dst_len, unsigned char rtm_src_len,
                              unsigned char rtm_tos, unsigned char rtm_table,
                              unsigned char rtm_scope, unsigned char rtm_protocol,
                              unsigned char rtm_type, unsigned flags, sd_rtnl_message **ret);
sd_rtnl_message *sd_rtnl_message_ref(sd_rtnl_message *m);
sd_rtnl_message *sd_rtnl_message_unref(sd_rtnl_message *m);

int sd_rtnl_message_get_type(sd_rtnl_message *m, uint16_t *type);
int sd_rtnl_message_append(sd_rtnl_message *m, unsigned short type, const void *data);
int sd_rtnl_message_read(sd_rtnl_message *m, unsigned short *type, void **data);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_rtnl*, sd_rtnl_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_rtnl_message*, sd_rtnl_message_unref);

#define _cleanup_sd_rtnl_unref_ _cleanup_(sd_rtnl_unrefp)
#define _cleanup_sd_rtnl_message_unref_ _cleanup_(sd_rtnl_message_unrefp)
