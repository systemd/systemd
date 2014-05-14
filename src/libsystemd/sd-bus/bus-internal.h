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
#include "kdbus.h"

struct reply_callback {
        sd_bus_message_handler_t callback;
        usec_t timeout;
        uint64_t cookie;
        unsigned prioq_idx;
};

struct filter_callback {
        sd_bus_message_handler_t callback;

        unsigned last_iteration;

        LIST_FIELDS(struct filter_callback, callbacks);
};

struct match_callback {
        sd_bus_message_handler_t callback;

        uint64_t cookie;
        unsigned last_iteration;

        char *match_string;

        struct bus_match_node *match_node;
};

struct node {
        char *path;
        struct node *parent;
        LIST_HEAD(struct node, child);
        LIST_FIELDS(struct node, siblings);

        LIST_HEAD(struct node_callback, callbacks);
        LIST_HEAD(struct node_vtable, vtables);
        LIST_HEAD(struct node_enumerator, enumerators);
        LIST_HEAD(struct node_object_manager, object_managers);
};

struct node_callback {
        struct node *node;

        bool is_fallback;
        sd_bus_message_handler_t callback;

        unsigned last_iteration;

        LIST_FIELDS(struct node_callback, callbacks);
};

struct node_enumerator {
        struct node *node;

        sd_bus_node_enumerator_t callback;

        unsigned last_iteration;

        LIST_FIELDS(struct node_enumerator, enumerators);
};

struct node_object_manager {
        struct node *node;

        LIST_FIELDS(struct node_object_manager, object_managers);
};

struct node_vtable {
        struct node *node;

        char *interface;
        bool is_fallback;
        const sd_bus_vtable *vtable;
        sd_bus_object_find_t find;

        unsigned last_iteration;

        LIST_FIELDS(struct node_vtable, vtables);
};

struct vtable_member {
        const char *path;
        const char *interface;
        const char *member;
        struct node_vtable *parent;
        unsigned last_iteration;
        const sd_bus_vtable *vtable;
};

typedef enum BusSlotType {
        BUS_REPLY_CALLBACK,
        BUS_FILTER_CALLBACK,
        BUS_MATCH_CALLBACK,
        BUS_NODE_CALLBACK,
        BUS_NODE_ENUMERATOR,
        BUS_NODE_VTABLE,
        BUS_NODE_OBJECT_MANAGER,
        _BUS_SLOT_INVALID = -1,
} BusSlotType;

struct sd_bus_slot {
        unsigned n_ref;
        sd_bus *bus;
        void *userdata;
        BusSlotType type:5;
        bool floating:1;

        LIST_FIELDS(sd_bus_slot, slots);

        union {
                struct reply_callback reply_callback;
                struct filter_callback filter_callback;
                struct match_callback match_callback;
                struct node_callback node_callback;
                struct node_enumerator node_enumerator;
                struct node_object_manager node_object_manager;
                struct node_vtable node_vtable;
        };
};

enum bus_state {
        BUS_UNSET,
        BUS_OPENING,
        BUS_AUTHENTICATING,
        BUS_HELLO,
        BUS_RUNNING,
        BUS_CLOSING,
        BUS_CLOSED
};

static inline bool BUS_IS_OPEN(enum bus_state state) {
        return state > BUS_UNSET && state < BUS_CLOSING;
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
        int message_endian;

        bool is_kernel:1;
        bool can_fds:1;
        bool bus_client:1;
        bool ucred_valid:1;
        bool is_server:1;
        bool anonymous_auth:1;
        bool prefer_readv:1;
        bool prefer_writev:1;
        bool match_callbacks_modified:1;
        bool filter_callbacks_modified:1;
        bool nodes_modified:1;
        bool trusted:1;
        bool fake_creds_valid:1;
        bool manual_peer_interface:1;
        bool is_system:1;
        bool is_user:1;

        int use_memfd;

        void *rbuffer;
        size_t rbuffer_size;

        sd_bus_message **rqueue;
        unsigned rqueue_size;
        size_t rqueue_allocated;

        sd_bus_message **wqueue;
        unsigned wqueue_size;
        size_t windex;
        size_t wqueue_allocated;

        uint64_t cookie;

        char *unique_name;
        uint64_t unique_id;

        struct bus_match_node match_callbacks;
        Prioq *reply_callbacks_prioq;
        Hashmap *reply_callbacks;
        LIST_HEAD(struct filter_callback, filter_callbacks);

        Hashmap *nodes;
        Hashmap *vtable_methods;
        Hashmap *vtable_properties;

        union {
                struct sockaddr sa;
                struct sockaddr_un un;
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
        } sockaddr;
        socklen_t sockaddr_size;

        char *kernel;
        char *machine;

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

        uint64_t creds_mask;

        int *fds;
        unsigned n_fds;

        char *exec_path;
        char **exec_argv;

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
        uint64_t attach_flags;

        uint64_t match_cookie;

        sd_event_source *input_io_event_source;
        sd_event_source *output_io_event_source;
        sd_event_source *time_event_source;
        sd_event_source *quit_event_source;
        sd_event *event;
        int event_priority;

        sd_bus_message *current_message;
        sd_bus_slot *current_slot;

        sd_bus **default_bus_ptr;
        pid_t tid;

        struct kdbus_creds fake_creds;
        char *fake_label;

        char *cgroup_root;

        char *connection_name;

        size_t bloom_size;
        unsigned bloom_n_hash;

        sd_bus_track *track_queue;

        LIST_HEAD(sd_bus_slot, slots);
};

#define BUS_DEFAULT_TIMEOUT ((usec_t) (25 * USEC_PER_SEC))

#define BUS_WQUEUE_MAX 1024
#define BUS_RQUEUE_MAX 64*1024

#define BUS_MESSAGE_SIZE_MAX (64*1024*1024)
#define BUS_AUTH_SIZE_MAX (64*1024)

#define BUS_CONTAINER_DEPTH 128

/* Defined by the specification as maximum size of an array in
 * bytes */
#define BUS_ARRAY_MAX_SIZE 67108864

#define BUS_FDS_MAX 1024

#define BUS_EXEC_ARGV_MAX 256

bool interface_name_is_valid(const char *p) _pure_;
bool service_name_is_valid(const char *p) _pure_;
bool member_name_is_valid(const char *p) _pure_;
bool object_path_is_valid(const char *p) _pure_;
char *object_path_startswith(const char *a, const char *b) _pure_;

bool namespace_complex_pattern(const char *pattern, const char *value) _pure_;
bool path_complex_pattern(const char *pattern, const char *value) _pure_;

bool namespace_simple_pattern(const char *pattern, const char *value) _pure_;
bool path_simple_pattern(const char *pattern, const char *value) _pure_;

int bus_message_type_from_string(const char *s, uint8_t *u) _pure_;
const char *bus_message_type_to_string(uint8_t u) _pure_;

#define error_name_is_valid interface_name_is_valid

int bus_ensure_running(sd_bus *bus);
int bus_start_running(sd_bus *bus);
int bus_next_address(sd_bus *bus);

int bus_seal_synthetic_message(sd_bus *b, sd_bus_message *m);

int bus_rqueue_make_room(sd_bus *bus);

bool bus_pid_changed(sd_bus *bus);

char *bus_address_escape(const char *v);

#define OBJECT_PATH_FOREACH_PREFIX(prefix, path)                        \
        for (char *_slash = ({ strcpy((prefix), (path)); streq((prefix), "/") ? NULL : strrchr((prefix), '/'); }) ; \
             _slash && !(_slash[(_slash) == (prefix)] = 0);             \
             _slash = streq((prefix), "/") ? NULL : strrchr((prefix), '/'))

/* If we are invoking callbacks of a bus object, ensure unreffing the
 * bus from the callback doesn't destroy the object we are working
 * on */
#define BUS_DONT_DESTROY(bus) \
        _cleanup_bus_unref_ _unused_ sd_bus *_dont_destroy_##bus = sd_bus_ref(bus)

int bus_set_address_system(sd_bus *bus);
int bus_set_address_user(sd_bus *bus);
int bus_set_address_system_remote(sd_bus *b, const char *host);
int bus_set_address_system_container(sd_bus *b, const char *machine);

int bus_remove_match_by_string(sd_bus *bus, const char *match, sd_bus_message_handler_t callback, void *userdata);
