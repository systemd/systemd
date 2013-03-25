/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "hashmap.h"
#include "prioq.h"
#include "list.h"
#include "util.h"

#include "sd-bus.h"
#include "bus-error.h"

struct reply_callback {
        sd_message_handler_t callback;
        void *userdata;
        usec_t timeout;
        uint64_t serial;
        unsigned prioq_idx;
};

struct filter_callback {
        sd_message_handler_t callback;
        void *userdata;

        LIST_FIELDS(struct filter_callback, callbacks);
};

struct object_callback {
        sd_message_handler_t callback;
        void *userdata;

        char *path;
        bool is_fallback;
};

enum bus_state {
        BUS_UNSET,
        BUS_OPENING,
        BUS_AUTHENTICATING,
        BUS_HELLO,
        BUS_RUNNING
};

struct sd_bus {
        unsigned n_ref;
        enum bus_state state;
        int fd;
        int message_version;

        bool negotiate_fds:1;
        bool can_fds:1;
        bool bus_client:1;
        bool ucred_valid:1;

        void *rbuffer;
        size_t rbuffer_size;

        sd_bus_message **rqueue;
        unsigned rqueue_size;

        sd_bus_message **wqueue;
        unsigned wqueue_size;
        size_t windex;

        uint64_t serial;

        char *unique_name;

        Prioq *reply_callbacks_prioq;
        Hashmap *reply_callbacks;
        LIST_HEAD(struct filter_callback, filter_callbacks);
        Hashmap *object_callbacks;

        union {
                struct sockaddr sa;
                struct sockaddr_un un;
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
        } sockaddr;
        socklen_t sockaddr_size;

        sd_id128_t peer;

        char *address;
        unsigned address_index;

        int last_connect_error;

        struct iovec auth_iovec[3];
        unsigned auth_index;
        size_t auth_size;
        char *auth_uid;
        usec_t auth_timeout;

        struct ucred ucred;
        char label[NAME_MAX];

        int *fds;
        unsigned n_fds;

        char *exec_path;
        char **exec_argv;
};

static inline void bus_unrefp(sd_bus **b) {
        sd_bus_unref(*b);
}

#define _cleanup_bus_unref_ __attribute__((cleanup(bus_unrefp)))
#define _cleanup_bus_error_free_ __attribute__((cleanup(sd_bus_error_free)))

#define BUS_DEFAULT_TIMEOUT ((usec_t) (25 * USEC_PER_SEC))

#define BUS_WQUEUE_MAX 128
#define BUS_RQUEUE_MAX 128

#define BUS_MESSAGE_SIZE_MAX (64*1024*1024)
#define BUS_AUTH_SIZE_MAX (64*1024)

#define BUS_CONTAINER_DEPTH 128

/* Defined by the specification as maximum size of an array in
 * bytes */
#define BUS_ARRAY_MAX_SIZE 67108864

#define BUS_FDS_MAX 1024

#define BUS_EXEC_ARGV_MAX 256

bool object_path_is_valid(const char *p);
bool interface_name_is_valid(const char *p);
bool service_name_is_valid(const char *p);
bool member_name_is_valid(const char *p);

#define error_name_is_valid interface_name_is_valid

int bus_ensure_running(sd_bus *bus);
int bus_start_running(sd_bus *bus);
int bus_next_address(sd_bus *bus);
