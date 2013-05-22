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
#include <pthread.h>

#include "hashmap.h"
#include "prioq.h"
#include "list.h"
#include "util.h"
#include "refcnt.h"

#include "sd-bus.h"
#include "bus-error.h"
#include "bus-match.h"
#include "bus-kernel.h"

struct reply_callback {
        sd_bus_message_handler_t callback;
        void *userdata;
        usec_t timeout;
        uint64_t serial;
        unsigned prioq_idx;
};

struct filter_callback {
        sd_bus_message_handler_t callback;
        void *userdata;

        unsigned last_iteration;

        LIST_FIELDS(struct filter_callback, callbacks);
};

struct object_callback {
        sd_bus_message_handler_t callback;
        void *userdata;

        char *path;
        bool is_fallback;

        unsigned last_iteration;
};

enum bus_state {
        BUS_UNSET,
        BUS_OPENING,
        BUS_AUTHENTICATING,
        BUS_HELLO,
        BUS_RUNNING,
        BUS_CLOSED
};

static inline bool BUS_IS_OPEN(enum bus_state state) {
        return state > BUS_UNSET && state < BUS_CLOSED;
}

enum bus_auth {
        _BUS_AUTH_INVALID,
        BUS_AUTH_EXTERNAL,
        BUS_AUTH_ANONYMOUS
};

struct sd_bus {
        /* We use atomic ref counting here since sd_bus_message
           objects retain references to their originating sd_bus but
           we want to allow them to be processed in a different
           thread. We won't provide full thread safety, but only the
           bare minimum that makes it possible to use sd_bus and
           sd_bus_message objects independently and on different
           threads as long as each object is used only once at the
           same time. */
        RefCount n_ref;

        enum bus_state state;
        int input_fd, output_fd;
        int message_version;

        bool is_kernel:1;
        bool can_fds:1;
        bool bus_client:1;
        bool ucred_valid:1;
        bool is_server:1;
        bool anonymous_auth:1;
        bool prefer_readv:1;
        bool prefer_writev:1;
        bool processing:1;
        bool match_callbacks_modified:1;
        bool filter_callbacks_modified:1;
        bool object_callbacks_modified:1;

        int use_memfd;

        void *rbuffer;
        size_t rbuffer_size;

        sd_bus_message **rqueue;
        unsigned rqueue_size;

        sd_bus_message **wqueue;
        unsigned wqueue_size;
        size_t windex;

        uint64_t serial;

        char *unique_name;

        struct bus_match_node match_callbacks;
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

        char *kernel;

        sd_id128_t server_id;

        char *address;
        unsigned address_index;

        int last_connect_error;

        enum bus_auth auth;
        size_t auth_rbegin;
        struct iovec auth_iovec[3];
        unsigned auth_index;
        char *auth_buffer;
        usec_t auth_timeout;

        struct ucred ucred;
        char label[NAME_MAX];

        int *fds;
        unsigned n_fds;

        char *exec_path;
        char **exec_argv;

        uint64_t hello_serial;
        unsigned iteration_counter;

        void *kdbus_buffer;

        /* We do locking around the memfd cache, since we want to
         * allow people to process a sd_bus_message in a different
         * thread then it was generated on and free it there. Since
         * adding something to the memfd cache might happen when a
         * message is released, we hence need to protect this bit with
         * a mutex. */
        pthread_mutex_t memfd_cache_mutex;
        struct memfd_cache memfd_cache[MEMFD_CACHE_MAX];
        unsigned n_memfd_cache;

        pid_t original_pid;

        uint64_t hello_flags;

        uint64_t match_cookie;
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

bool namespace_complex_pattern(const char *pattern, const char *value);
bool path_complex_pattern(const char *pattern, const char *value);

bool namespace_simple_pattern(const char *pattern, const char *value);
bool path_simple_pattern(const char *pattern, const char *value);

int bus_message_type_from_string(const char *s, uint8_t *u);
const char *bus_message_type_to_string(uint8_t u);

#define error_name_is_valid interface_name_is_valid

int bus_ensure_running(sd_bus *bus);
int bus_start_running(sd_bus *bus);
int bus_next_address(sd_bus *bus);

bool bus_pid_changed(sd_bus *bus);
