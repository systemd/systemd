/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "bus-forward.h"
#include "bus-kernel.h"
#include "bus-match.h"
#include "constants.h"
#include "list.h"
#include "runtime-scope.h"
#include "socket-util.h"

/* Note that we use the new /run prefix here (instead of /var/run) since we require them to be aliases and
 * that way we become independent of /var being mounted */
#define DEFAULT_SYSTEM_BUS_ADDRESS "unix:path=/run/dbus/system_bus_socket"
#define DEFAULT_USER_BUS_ADDRESS_FMT "unix:path=%s/bus"

typedef struct BusReplyCallback {
        sd_bus_message_handler_t callback;
        usec_t timeout_usec; /* this is a relative timeout until we reach the BUS_HELLO state, and an absolute one right after */
        uint64_t cookie;
        unsigned prioq_idx;
} BusReplyCallback;

typedef struct BusFilterCallback {
        sd_bus_message_handler_t callback;

        unsigned last_iteration;

        LIST_FIELDS(BusFilterCallback, callbacks);
} BusFilterCallback;

typedef struct BusNode {
        char *path;
        BusNode *parent;
        LIST_HEAD(BusNode, child);
        LIST_FIELDS(BusNode, siblings);

        LIST_HEAD(BusNodeCallback, callbacks);
        LIST_HEAD(BusNodeVTable, vtables);
        LIST_HEAD(BusNodeEnumerator, enumerators);
        LIST_HEAD(BusNodeObjectManager, object_managers);
} BusNode;

typedef struct BusNodeCallback {
        BusNode *node;

        bool is_fallback;
        unsigned last_iteration;

        sd_bus_message_handler_t callback;

        LIST_FIELDS(BusNodeCallback, callbacks);
} BusNodeCallback;

typedef struct BusNodeEnumerator {
        BusNode *node;

        sd_bus_node_enumerator_t callback;

        unsigned last_iteration;

        LIST_FIELDS(BusNodeEnumerator, enumerators);
} BusNodeEnumerator;

typedef struct BusNodeObjectManager {
        BusNode *node;

        LIST_FIELDS(BusNodeObjectManager, object_managers);
} BusNodeObjectManager;

typedef struct BusNodeVTable {
        BusNode *node;

        bool is_fallback;
        unsigned last_iteration;

        char *interface;
        const sd_bus_vtable *vtable;
        sd_bus_object_find_t find;

        LIST_FIELDS(BusNodeVTable, vtables);
} BusNodeVTable;

typedef struct BusVTableMember {
        const char *path;
        const char *interface;
        const char *member;
        BusNodeVTable *parent;
        unsigned last_iteration;
        const sd_bus_vtable *vtable;
} BusVTableMember;

typedef enum BusSlotType {
        BUS_REPLY_CALLBACK,
        BUS_FILTER_CALLBACK,
        BUS_MATCH_CALLBACK,
        BUS_NODE_CALLBACK,
        BUS_NODE_ENUMERATOR,
        BUS_NODE_VTABLE,
        BUS_NODE_OBJECT_MANAGER,
        _BUS_SLOT_INVALID = -EINVAL,
} BusSlotType;

typedef struct sd_bus_slot {
        unsigned n_ref;
        BusSlotType type:8;

        /* Slots can be "floating" or not. If they are not floating (the usual case) then they reference the
         * bus object they are associated with. This means the bus object stays allocated at least as long as
         * there is a slot around associated with it. If it is floating, then the slot's lifecycle is bound
         * to the lifecycle of the bus: it will be disconnected from the bus when the bus is destroyed, and
         * it keeping the slot reffed hence won't mean the bus stays reffed too. Internally this means the
         * reference direction is reversed: floating slots objects are referenced by the bus object, and not
         * vice versa. */
        bool floating;
        bool match_added;

        sd_bus *bus;
        void *userdata;
        sd_bus_destroy_t destroy_callback;

        char *description;

        LIST_FIELDS(sd_bus_slot, slots);

        union {
                BusReplyCallback reply_callback;
                BusFilterCallback filter_callback;
                BusMatchCallback match_callback;
                BusNodeCallback node_callback;
                BusNodeEnumerator node_enumerator;
                BusNodeObjectManager node_object_manager;
                BusNodeVTable node_vtable;
        };
} sd_bus_slot;

typedef enum BusState {
        BUS_UNSET,
        BUS_WATCH_BIND,      /* waiting for the socket to appear via inotify */
        BUS_OPENING,         /* the kernel's connect() is still not ready */
        BUS_AUTHENTICATING,  /* we are currently in the "SASL" authorization phase of dbus */
        BUS_HELLO,           /* we are waiting for the Hello() response */
        BUS_RUNNING,
        BUS_CLOSING,
        BUS_CLOSED,
        _BUS_STATE_MAX,
} BusState;

static inline bool BUS_IS_OPEN(BusState state) {
        return state > BUS_UNSET && state < BUS_CLOSING;
}

typedef enum BusAuth {
        _BUS_AUTH_INVALID,
        BUS_AUTH_EXTERNAL,
        BUS_AUTH_ANONYMOUS
} BusAuth;

typedef struct sd_bus {
        unsigned n_ref;

        BusState state;
        int input_fd, output_fd;
        int inotify_fd;
        int message_version;
        int message_endian;

        bool can_fds;
        bool bus_client;
        bool ucred_valid;
        bool is_server;
        bool anonymous_auth;
        bool prefer_readv;
        bool prefer_writev;
        bool match_callbacks_modified;
        bool filter_callbacks_modified;
        bool nodes_modified;
        bool trusted;
        bool manual_peer_interface;
        bool allow_interactive_authorization;
        bool exit_on_disconnect;
        bool exited;
        bool exit_triggered;
        bool is_local;
        bool watch_bind;
        bool is_monitor;
        bool accept_fd;
        bool attach_timestamp;
        bool connected_signal;
        bool close_on_exit;

        RuntimeScope runtime_scope;

        int use_memfd;

        void *rbuffer;
        size_t rbuffer_size;

        sd_bus_message **rqueue;
        size_t rqueue_size;

        sd_bus_message **wqueue;
        size_t wqueue_size;
        size_t windex;

        uint64_t cookie;
        uint64_t read_counter; /* A counter for each incoming msg */

        char *unique_name;
        uint64_t unique_id;

        BusMatchNode match_callbacks;
        Prioq *reply_callbacks_prioq;
        OrderedHashmap *reply_callbacks;
        LIST_HEAD(BusFilterCallback, filter_callbacks);

        Hashmap *nodes;
        Set *vtable_methods;
        Set *vtable_properties;

        union sockaddr_union sockaddr;
        socklen_t sockaddr_size;

        pid_t nspid;
        char *machine;

        sd_id128_t server_id;

        char *address;
        unsigned address_index;

        uid_t connect_as_uid;
        gid_t connect_as_gid;

        int last_connect_error;

        BusAuth auth;
        unsigned auth_index;
        struct iovec auth_iovec[3];
        size_t auth_rbegin;
        char *auth_buffer;
        usec_t auth_timeout;

        struct ucred ucred;
        char *label;
        gid_t *groups;
        size_t n_groups;
        union sockaddr_union sockaddr_peer;
        socklen_t sockaddr_size_peer;
        int pidfd;

        uint64_t creds_mask;

        int *fds;
        size_t n_fds;

        char *exec_path;
        char **exec_argv;

        /* We do locking around the memfd cache, since we want to
         * allow people to process a sd_bus_message in a different
         * thread then it was generated on and free it there. Since
         * adding something to the memfd cache might happen when a
         * message is released, we hence need to protect this bit with
         * a mutex. */
        pthread_mutex_t memfd_cache_mutex;
        struct memfd_cache memfd_cache[MEMFD_CACHE_MAX];
        unsigned n_memfd_cache;

        uint64_t origin_id;
        pid_t busexec_pid;

        unsigned iteration_counter;

        sd_event_source *input_io_event_source;
        sd_event_source *output_io_event_source;
        sd_event_source *time_event_source;
        sd_event_source *quit_event_source;
        sd_event_source *inotify_event_source;
        sd_event *event;
        int event_priority;

        pid_t tid;

        sd_bus_message *current_message;
        sd_bus_slot *current_slot;
        sd_bus_message_handler_t current_handler;
        void *current_userdata;

        sd_bus **default_bus_ptr;

        char *description;
        char *patch_sender;

        sd_bus_track *track_queue;

        LIST_HEAD(sd_bus_slot, slots);
        LIST_HEAD(sd_bus_track, tracks);

        int *inotify_watches;
        size_t n_inotify_watches;

        /* zero means use value specified by $SYSTEMD_BUS_TIMEOUT= environment variable or built-in default */
        usec_t method_call_timeout;
} sd_bus;

/* For method calls we timeout at 25s, like in the D-Bus reference implementation */
#define BUS_DEFAULT_TIMEOUT ((usec_t) (25 * USEC_PER_SEC))

/* For the authentication phase we grant 90s, to provide extra room during boot, when RNGs and such are not filled up
 * with enough entropy yet and might delay the boot */
#define BUS_AUTH_TIMEOUT ((usec_t) DEFAULT_TIMEOUT_USEC)

#define BUS_WQUEUE_MAX (384*1024)
#define BUS_RQUEUE_MAX (384*1024)

#define BUS_MESSAGE_SIZE_MAX (128*1024*1024)
#define BUS_AUTH_SIZE_MAX (64*1024)
/* Note that the D-Bus specification states that bus paths shall have no size limit. We enforce here one
 * anyway, since truly unbounded strings are a security problem. The limit we pick is relatively large however,
 * to not clash unnecessarily with real-life applications. */
#define BUS_PATH_SIZE_MAX (64*1024)

#define BUS_CONTAINER_DEPTH 128

/* Defined by the specification as maximum size of an array in bytes */
#define BUS_ARRAY_MAX_SIZE 67108864

#define BUS_FDS_MAX 1024

#define BUS_EXEC_ARGV_MAX 256

bool interface_name_is_valid(const char *p) _pure_;
bool service_name_is_valid(const char *p) _pure_;
bool member_name_is_valid(const char *p) _pure_;
bool object_path_is_valid(const char *p) _pure_;

char* object_path_startswith(const char *a, const char *b) _pure_;

bool namespace_complex_pattern(const char *pattern, const char *value) _pure_;
bool path_complex_pattern(const char *pattern, const char *value) _pure_;

bool namespace_simple_pattern(const char *pattern, const char *value) _pure_;
bool path_simple_pattern(const char *pattern, const char *value) _pure_;

int bus_message_type_from_string(const char *s, uint8_t *u);
const char* bus_message_type_to_string(uint8_t u) _pure_;

#define error_name_is_valid interface_name_is_valid

sd_bus *bus_resolve(sd_bus *bus);

int bus_ensure_running(sd_bus *bus);
int bus_start_running(sd_bus *bus);
int bus_next_address(sd_bus *bus);

int bus_seal_synthetic_message(sd_bus *b, sd_bus_message *m);

int bus_rqueue_make_room(sd_bus *bus);

bool bus_origin_changed(sd_bus *bus);

char* bus_address_escape(const char *v);

int bus_attach_io_events(sd_bus *b);
int bus_attach_inotify_event(sd_bus *b);

void bus_close_inotify_fd(sd_bus *b);
void bus_close_io_fds(sd_bus *b);

int bus_add_match_full(
                sd_bus *bus,
                sd_bus_slot **slot,
                bool asynchronous,
                const char *match,
                sd_bus_message_handler_t callback,
                sd_bus_message_handler_t install_callback,
                void *userdata,
                uint64_t timeout_usec);

#define OBJECT_PATH_FOREACH_PREFIX(prefix, path)                        \
        for (char *_slash = ({ strcpy((prefix), (path)); streq((prefix), "/") ? NULL : strrchr((prefix), '/'); }) ; \
             _slash && ((_slash[(_slash) == (prefix)] = 0), true);       \
             _slash = streq((prefix), "/") ? NULL : strrchr((prefix), '/'))

/* If we are invoking callbacks of a bus object, ensure unreffing the
 * bus from the callback doesn't destroy the object we are working on */
#define BUS_DONT_DESTROY(bus) \
        _cleanup_(sd_bus_unrefp) _unused_ sd_bus *_dont_destroy_##bus = sd_bus_ref(bus)

int bus_set_address_system(sd_bus *bus);
int bus_set_address_user(sd_bus *bus);
int bus_set_address_system_remote(sd_bus *b, const char *host);
int bus_set_address_machine(sd_bus *b, RuntimeScope runtime_scope, const char *machine);

int bus_maybe_reply_error(sd_bus_message *m, int r, const sd_bus_error *e);

#define bus_assert_return(expr, r, error)                               \
        do {                                                            \
                if (!assert_log(expr))                                  \
                        return sd_bus_error_set_errno(error, r);        \
        } while (false)

void bus_enter_closing(sd_bus *bus);

void bus_set_state(sd_bus *bus, BusState state);
