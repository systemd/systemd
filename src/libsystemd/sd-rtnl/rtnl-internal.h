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

#include "refcnt.h"
#include "prioq.h"
#include "list.h"

#include "sd-rtnl.h"

#define RTNL_DEFAULT_TIMEOUT ((usec_t) (10 * USEC_PER_SEC))

#define RTNL_WQUEUE_MAX 1024
#define RTNL_RQUEUE_MAX 64*1024

#define RTNL_CONTAINER_DEPTH 32

struct reply_callback {
        sd_rtnl_message_handler_t callback;
        void *userdata;
        usec_t timeout;
        uint64_t serial;
        unsigned prioq_idx;
};

struct match_callback {
        sd_rtnl_message_handler_t callback;
        uint16_t type;
        void *userdata;

        LIST_FIELDS(struct match_callback, match_callbacks);
};

struct sd_rtnl {
        RefCount n_ref;

        int fd;

        union {
                struct sockaddr sa;
                struct sockaddr_nl nl;
        } sockaddr;

        sd_rtnl_message **rqueue;
        unsigned rqueue_size;

        sd_rtnl_message **wqueue;
        unsigned wqueue_size;

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

struct sd_rtnl_message {
        RefCount n_ref;

        sd_rtnl *rtnl;

        struct nlmsghdr *hdr;
        size_t container_offsets[RTNL_CONTAINER_DEPTH]; /* offset from hdr to each container's start */
        unsigned n_containers; /* number of containers */
        size_t next_rta_offset; /* offset from hdr to next rta */

        bool sealed:1;
};

int message_new(sd_rtnl *rtnl, sd_rtnl_message **ret, size_t initial_size);

int socket_write_message(sd_rtnl *nl, sd_rtnl_message *m);
int socket_read_message(sd_rtnl *nl, sd_rtnl_message **ret);

/* Make sure callbacks don't destroy the rtnl connection */
#define RTNL_DONT_DESTROY(rtnl) \
        _cleanup_rtnl_unref_ _unused_ sd_rtnl *_dont_destroy_##rtnl = sd_rtnl_ref(rtnl)
