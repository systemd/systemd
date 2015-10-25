/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <linux/netlink.h>

#include "sd-netlink.h"

#include "list.h"
#include "netlink-types.h"
#include "prioq.h"
#include "refcnt.h"

#define RTNL_DEFAULT_TIMEOUT ((usec_t) (25 * USEC_PER_SEC))

#define RTNL_WQUEUE_MAX 1024
#define RTNL_RQUEUE_MAX 64*1024

#define RTNL_CONTAINER_DEPTH 32

struct reply_callback {
        sd_netlink_message_handler_t callback;
        void *userdata;
        usec_t timeout;
        uint64_t serial;
        unsigned prioq_idx;
};

struct match_callback {
        sd_netlink_message_handler_t callback;
        uint16_t type;
        void *userdata;

        LIST_FIELDS(struct match_callback, match_callbacks);
};

struct sd_netlink {
        RefCount n_ref;

        int fd;

        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sockaddr;

        Hashmap *broadcast_group_refs;
        bool broadcast_group_dont_leave:1; /* until we can rely on 4.2 */

        sd_netlink_message **rqueue;
        unsigned rqueue_size;
        size_t rqueue_allocated;

        sd_netlink_message **rqueue_partial;
        unsigned rqueue_partial_size;
        size_t rqueue_partial_allocated;

        struct nlmsghdr *rbuffer;
        size_t rbuffer_allocated;

        bool processing:1;

        uint32_t serial;

        struct Prioq *reply_callbacks_prioq;
        Hashmap *reply_callbacks;

        LIST_HEAD(struct match_callback, match_callbacks);

        pid_t original_pid;

        sd_event_source *io_event_source;
        sd_event_source *time_event_source;
        sd_event_source *exit_event_source;
        sd_event *event;
};

struct netlink_attribute {
        size_t offset; /* offset from hdr to attribute */
        bool nested:1;
        bool net_byteorder:1;
};

struct netlink_container {
        const struct NLTypeSystem *type_system; /* the type system of the container */
        size_t offset; /* offset from hdr to the start of the container */
        struct netlink_attribute *attributes;
        unsigned short n_attributes; /* number of attributes in container */
};

struct sd_netlink_message {
        RefCount n_ref;

        sd_netlink *rtnl;

        struct nlmsghdr *hdr;
        struct netlink_container containers[RTNL_CONTAINER_DEPTH];
        unsigned n_containers; /* number of containers */
        bool sealed:1;
        bool broadcast:1;

        sd_netlink_message *next; /* next in a chain of multi-part messages */
};

int message_new(sd_netlink *rtnl, sd_netlink_message **ret, uint16_t type);
int message_new_empty(sd_netlink *rtnl, sd_netlink_message **ret);

int socket_open(int family);
int socket_bind(sd_netlink *nl);
int socket_broadcast_group_ref(sd_netlink *nl, unsigned group);
int socket_broadcast_group_unref(sd_netlink *nl, unsigned group);
int socket_write_message(sd_netlink *nl, sd_netlink_message *m);
int socket_read_message(sd_netlink *nl);

int rtnl_rqueue_make_room(sd_netlink *rtnl);
int rtnl_rqueue_partial_make_room(sd_netlink *rtnl);

/* Make sure callbacks don't destroy the rtnl connection */
#define RTNL_DONT_DESTROY(rtnl) \
        _cleanup_netlink_unref_ _unused_ sd_netlink *_dont_destroy_##rtnl = sd_netlink_ref(rtnl)
