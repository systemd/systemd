/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "sd-varlink.h"

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

typedef struct VarlinkJsonQueueItem VarlinkJsonQueueItem;

/* A queued message we shall write into the socket, along with the file descriptors to send at the same
 * time. This queue item binds them together so that message/fd boundaries are maintained throughout the
 * whole pipeline. */
struct VarlinkJsonQueueItem {
        LIST_FIELDS(VarlinkJsonQueueItem, queue);
        sd_json_variant *data;
        size_t n_fds;
        int fds[];
};

typedef struct sd_varlink {
        unsigned n_ref;

        sd_varlink_server *server;

        VarlinkState state;
        bool connecting; /* This boolean indicates whether the socket fd we are operating on is currently
                          * processing an asynchronous connect(). In that state we watch the socket for
                          * EPOLLOUT, but we refrain from calling read() or write() on the socket as that
                          * will trigger ENOTCONN. Note that this boolean is kept separate from the
                          * VarlinkState above on purpose: while the connect() is still not complete we
                          * already want to allow queuing of messages and similar. Thus it's nice to keep
                          * these two state concepts separate: the VarlinkState encodes what our own view of
                          * the connection is, i.e. whether we think it's a server, a client, and has
                          * something queued already, while 'connecting' tells us a detail about the
                          * transport used below, that should have no effect on how we otherwise accept and
                          * process operations from the user.
                          *
                          * Or to say this differently: VARLINK_STATE_IS_ALIVE(state) tells you whether the
                          * connection is good to use, even if it might not be fully connected
                          * yet. connecting=true then informs you that actually we are still connecting, and
                          * the connection is actually not established yet and thus any requests you enqueue
                          * now will still work fine but will be queued only, not sent yet, but that
                          * shouldn't stop you from using the connection, since eventually whatever you queue
                          * *will* be sent.
                          *
                          * Or to say this even differently: 'state' is a high-level ("application layer"
                          * high, if you so will) state, while 'conecting' is a low-level ("transport layer"
                          * low, if you so will) state, and while they are not entirely unrelated and
                          * sometimes propagate effects to each other they are only asynchronously connected
                          * at most. */
        unsigned n_pending;

        int input_fd;
        int output_fd;

        char *input_buffer; /* valid data starts at input_buffer_index, ends at input_buffer_index+input_buffer_size */
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned;

        void *input_control_buffer;
        size_t input_control_buffer_size;

        char *output_buffer; /* valid data starts at output_buffer_index, ends at output_buffer_index+output_buffer_size */
        size_t output_buffer_index;
        size_t output_buffer_size;

        int *input_fds; /* file descriptors associated with the data in input_buffer (for fd passing) */
        size_t n_input_fds;

        int *output_fds; /* file descriptors associated with the data in output_buffer (for fd passing) */
        size_t n_output_fds;

        /* Further messages to output not yet formatted into text, and thus not included in output_buffer
         * yet. We keep them separate from output_buffer, to not violate fd message boundaries: we want that
         * each fd that is sent is associated with its fds, and that fds cannot be accidentally associated
         * with preceding or following messages. */
        LIST_HEAD(VarlinkJsonQueueItem, output_queue);
        VarlinkJsonQueueItem *output_queue_tail;
        size_t n_output_queue;

        /* The fds to associate with the next message that is about to be enqueued. The user first pushes the
         * fds it intends to send via varlink_push_fd() into this queue, and then once the message data is
         * submitted we'll combine the fds and the message data into one. */
        int *pushed_fds;
        size_t n_pushed_fds;

        sd_varlink_reply_t reply_callback;

        sd_json_variant *current;
        sd_json_variant *current_collected;
        sd_varlink_reply_flags_t current_reply_flags;
        sd_varlink_symbol *current_method;

        VarlinkJsonQueueItem *previous;
        char *sentinel;

        int peer_pidfd;
        struct ucred ucred;
        bool ucred_acquired:1;

        bool write_disconnected:1;
        bool read_disconnected:1;
        bool prefer_read:1;
        bool prefer_write:1;
        bool got_pollhup:1;

        bool output_buffer_sensitive:1; /* whether to erase the output buffer after writing it to the socket */
        bool input_sensitive:1; /* Whether incoming messages might be sensitive */

        bool allow_fd_passing_output;
        int allow_fd_passing_input;

        int af; /* address family if socket; AF_UNSPEC if not socket; negative if not known */

        usec_t timestamp;
        usec_t timeout;

        void *userdata;
        char *description;

        sd_event *event;
        sd_event_source *input_event_source;
        sd_event_source *output_event_source;
        sd_event_source *time_event_source;
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

        unsigned n_connections;
        Hashmap *by_uid;               /* UID_TO_PTR(uid) → UINT_TO_PTR(n_connections) */

        void *userdata;

        char *description;
        char *vendor;
        char *product;
        char *version;
        char *url;

        unsigned connections_max;
        unsigned connections_per_uid_max;

        bool exit_on_idle;
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
        return (v ? v->description : NULL) ?: "varlink";
}

static inline const char* varlink_server_description(sd_varlink_server *s) {
        return (s ? s->description : NULL) ?: "varlink";
}

VarlinkServerSocket* varlink_server_socket_free(VarlinkServerSocket *ss);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkServerSocket *, varlink_server_socket_free);

int varlink_server_add_socket_event_source(sd_varlink_server *s, VarlinkServerSocket *ss);
