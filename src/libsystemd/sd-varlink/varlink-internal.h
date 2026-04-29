/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "sd-varlink.h"

#include "json-stream.h"
#include "list.h"
#include "pidref.h"
#include "sd-forward.h"

typedef enum VarlinkState {
        /* Client side states */
        VARLINK_IDLE_CLIENT,
        VARLINK_AWAITING_REPLY,
        VARLINK_AWAITING_REPLY_MORE,
        VARLINK_CALLING,
        VARLINK_CALLED,
        VARLINK_COLLECTING,
        VARLINK_COLLECTING_REPLY,
        VARLINK_PROCESSING_REPLY,

        /* Server side states */
        VARLINK_IDLE_SERVER,
        VARLINK_PROCESSING_METHOD,
        VARLINK_PROCESSING_METHOD_MORE,
        VARLINK_PROCESSING_METHOD_ONEWAY,
        VARLINK_PROCESSED_METHOD,
        VARLINK_PENDING_METHOD,
        VARLINK_PENDING_METHOD_MORE,

        /* Common states (only during shutdown) */
        VARLINK_PENDING_DISCONNECT,
        VARLINK_PENDING_TIMEOUT,
        VARLINK_PROCESSING_DISCONNECT,
        VARLINK_PROCESSING_TIMEOUT,
        VARLINK_PROCESSING_FAILURE,
        VARLINK_DISCONNECTED,

        _VARLINK_STATE_MAX,
        _VARLINK_STATE_INVALID = -EINVAL,
} VarlinkState;

/* Tests whether we are not yet disconnected. Note that this is true during all states where the connection
 * is still good for something, and false only when it's dead for good. This means: when we are
 * asynchronously connecting to a peer and the connect() is still pending, then this will return 'true', as
 * the connection is still good, and we are likely to be able to properly operate on it soon. */
#define VARLINK_STATE_IS_ALIVE(state)                   \
        IN_SET(state,                                   \
               VARLINK_IDLE_CLIENT,                     \
               VARLINK_AWAITING_REPLY,                  \
               VARLINK_AWAITING_REPLY_MORE,             \
               VARLINK_CALLING,                         \
               VARLINK_CALLED,                          \
               VARLINK_COLLECTING,                      \
               VARLINK_COLLECTING_REPLY,                \
               VARLINK_PROCESSING_REPLY,                \
               VARLINK_IDLE_SERVER,                     \
               VARLINK_PROCESSING_METHOD,               \
               VARLINK_PROCESSING_METHOD_MORE,          \
               VARLINK_PROCESSING_METHOD_ONEWAY,        \
               VARLINK_PROCESSED_METHOD,                \
               VARLINK_PENDING_METHOD,                  \
               VARLINK_PENDING_METHOD_MORE)

/* Tests whether we are expected to generate a method call reply, i.e. are processing a method call, except
 * one with the ONEWAY flag set. */
#define VARLINK_STATE_WANTS_REPLY(state)                \
        IN_SET(state,                                   \
               VARLINK_PROCESSING_METHOD,               \
               VARLINK_PROCESSING_METHOD_MORE)

typedef struct sd_varlink {
        unsigned n_ref;

        VarlinkState state;
        sd_varlink_server *server;

        /* Transport layer: input/output buffers, fd passing, output queue, read/write/parse
         * step functions, sd-event integration (input/output/time event sources, idle
         * timeout, description, peer credentials). The varlink-level state machine and
         * dispatch logic live in sd-varlink.c; everything else about moving bytes is
         * delegated. */
        JsonStream stream;

        unsigned n_pending;

        /* Per-call protocol-upgrade marker: set when the *current* method call carries the
         * SD_VARLINK_METHOD_UPGRADE flag. Validated by sd_varlink_reply_and_upgrade() to
         * ensure the caller's contract is honored. The transport-layer "stop reading at the
         * next message boundary" behavior is governed independently by the JsonStream's
         * bounded_reads flag. */
        bool protocol_upgrade;

        sd_varlink_reply_t reply_callback;

        sd_json_variant *current;
        sd_json_variant *current_collected;
        sd_varlink_reply_flags_t current_reply_flags;
        sd_varlink_symbol *current_method;

        int *pushed_fds;
        size_t n_pushed_fds;

        sd_json_variant *previous;
        int *previous_fds;
        size_t n_previous_fds;
        char *sentinel;

        void *userdata;

        sd_event_source *quit_event_source;
        sd_event_source *defer_event_source;

        PidRef exec_pidref;
} sd_varlink;

typedef struct VarlinkServerSocket VarlinkServerSocket;

struct VarlinkServerSocket {
        sd_varlink_server *server;

        int fd;
        char *address;

        sd_event_source *event_source;

        LIST_FIELDS(VarlinkServerSocket, sockets);
};

typedef struct sd_varlink_server {
        unsigned n_ref;
        sd_varlink_server_flags_t flags;

        LIST_HEAD(VarlinkServerSocket, sockets);

        Hashmap *methods;              /* Fully qualified symbol name of a method → VarlinkMethod */
        Hashmap *interfaces;           /* Fully qualified interface name → VarlinkInterface* */
        Hashmap *symbols;              /* Fully qualified symbol name of method/error → VarlinkSymbol* */
        sd_varlink_connect_t connect_callback;
        sd_varlink_disconnect_t disconnect_callback;

        sd_event *event;
        int64_t event_priority;

        Hashmap *by_uid;               /* UID_TO_PTR(uid) → UINT_TO_PTR(n_connections) */
        unsigned n_connections;
        unsigned connections_max;
        unsigned connections_per_uid_max;

        bool exit_on_idle;

        void *userdata;

        char *description;
        char *vendor;
        char *product;
        char *version;
        char *url;
} sd_varlink_server;

#define varlink_log_errno(v, error, fmt, ...)                           \
        log_debug_errno(error, "%s: " fmt, varlink_description(v), ##__VA_ARGS__)

#define varlink_log(v, fmt, ...)                                        \
        log_debug("%s: " fmt, varlink_description(v), ##__VA_ARGS__)

#define varlink_server_log_errno(s, error, fmt, ...) \
        log_debug_errno(error, "%s: " fmt, varlink_server_description(s), ##__VA_ARGS__)

#define varlink_server_log(s, fmt, ...) \
        log_debug("%s: " fmt, varlink_server_description(s), ##__VA_ARGS__)

static inline const char* varlink_description(sd_varlink *v) {
        return (v ? json_stream_get_description(&v->stream) : NULL) ?: "varlink";
}

static inline const char* varlink_server_description(sd_varlink_server *s) {
        return (s ? s->description : NULL) ?: "varlink";
}

VarlinkServerSocket* varlink_server_socket_free(VarlinkServerSocket *ss);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkServerSocket *, varlink_server_socket_free);

int varlink_server_add_socket_event_source(sd_varlink_server *s, VarlinkServerSocket *ss);
