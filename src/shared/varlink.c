/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <malloc.h>
#include <poll.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "list.h"
#include "process-util.h"
#include "selinux-util.h"
#include "set.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "varlink.h"

#define VARLINK_DEFAULT_CONNECTIONS_MAX 4096U
#define VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX 1024U

#define VARLINK_DEFAULT_TIMEOUT_USEC (45U*USEC_PER_SEC)
#define VARLINK_BUFFER_MAX (16U*1024U*1024U)
#define VARLINK_READ_SIZE (64U*1024U)

typedef enum VarlinkState {
        /* Client side states */
        VARLINK_IDLE_CLIENT,
        VARLINK_AWAITING_REPLY,
        VARLINK_AWAITING_REPLY_MORE,
        VARLINK_CALLING,
        VARLINK_CALLED,
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
               VARLINK_PROCESSING_REPLY,                \
               VARLINK_IDLE_SERVER,                     \
               VARLINK_PROCESSING_METHOD,               \
               VARLINK_PROCESSING_METHOD_MORE,          \
               VARLINK_PROCESSING_METHOD_ONEWAY,        \
               VARLINK_PROCESSED_METHOD,                \
               VARLINK_PENDING_METHOD,                  \
               VARLINK_PENDING_METHOD_MORE)

struct Varlink {
        unsigned n_ref;

        VarlinkServer *server;

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

        int fd;

        char *input_buffer; /* valid data starts at input_buffer_index, ends at input_buffer_index+input_buffer_size */
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned;

        char *output_buffer; /* valid data starts at output_buffer_index, ends at output_buffer_index+output_buffer_size */
        size_t output_buffer_index;
        size_t output_buffer_size;

        VarlinkReply reply_callback;

        JsonVariant *current;
        JsonVariant *reply;

        struct ucred ucred;
        bool ucred_acquired:1;

        bool write_disconnected:1;
        bool read_disconnected:1;
        bool prefer_read_write:1;
        bool got_pollhup:1;

        usec_t timestamp;
        usec_t timeout;

        void *userdata;
        char *description;

        sd_event *event;
        sd_event_source *io_event_source;
        sd_event_source *time_event_source;
        sd_event_source *quit_event_source;
        sd_event_source *defer_event_source;
};

typedef struct VarlinkServerSocket VarlinkServerSocket;

struct VarlinkServerSocket {
        VarlinkServer *server;

        int fd;
        char *address;

        sd_event_source *event_source;

        LIST_FIELDS(VarlinkServerSocket, sockets);
};

struct VarlinkServer {
        unsigned n_ref;
        VarlinkServerFlags flags;

        LIST_HEAD(VarlinkServerSocket, sockets);

        Hashmap *methods;
        VarlinkConnect connect_callback;
        VarlinkDisconnect disconnect_callback;

        sd_event *event;
        int64_t event_priority;

        unsigned n_connections;
        Hashmap *by_uid;

        void *userdata;
        char *description;

        unsigned connections_max;
        unsigned connections_per_uid_max;
};

static const char* const varlink_state_table[_VARLINK_STATE_MAX] = {
        [VARLINK_IDLE_CLIENT]              = "idle-client",
        [VARLINK_AWAITING_REPLY]           = "awaiting-reply",
        [VARLINK_AWAITING_REPLY_MORE]      = "awaiting-reply-more",
        [VARLINK_CALLING]                  = "calling",
        [VARLINK_CALLED]                   = "called",
        [VARLINK_PROCESSING_REPLY]         = "processing-reply",
        [VARLINK_IDLE_SERVER]              = "idle-server",
        [VARLINK_PROCESSING_METHOD]        = "processing-method",
        [VARLINK_PROCESSING_METHOD_MORE]   = "processing-method-more",
        [VARLINK_PROCESSING_METHOD_ONEWAY] = "processing-method-oneway",
        [VARLINK_PROCESSED_METHOD]         = "processed-method",
        [VARLINK_PENDING_METHOD]           = "pending-method",
        [VARLINK_PENDING_METHOD_MORE]      = "pending-method-more",
        [VARLINK_PENDING_DISCONNECT]       = "pending-disconnect",
        [VARLINK_PENDING_TIMEOUT]          = "pending-timeout",
        [VARLINK_PROCESSING_DISCONNECT]    = "processing-disconnect",
        [VARLINK_PROCESSING_TIMEOUT]       = "processing-timeout",
        [VARLINK_PROCESSING_FAILURE]       = "processing-failure",
        [VARLINK_DISCONNECTED]             = "disconnected",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(varlink_state, VarlinkState);

#define varlink_log_errno(v, error, fmt, ...)                           \
        log_debug_errno(error, "%s: " fmt, varlink_description(v), ##__VA_ARGS__)

#define varlink_log(v, fmt, ...)                                        \
        log_debug("%s: " fmt, varlink_description(v), ##__VA_ARGS__)

#define varlink_server_log_errno(s, error, fmt, ...) \
        log_debug_errno(error, "%s: " fmt, varlink_server_description(s), ##__VA_ARGS__)

#define varlink_server_log(s, fmt, ...) \
        log_debug("%s: " fmt, varlink_server_description(s), ##__VA_ARGS__)

static inline const char *varlink_description(Varlink *v) {
        return (v ? v->description : NULL) ?: "varlink";
}

static inline const char *varlink_server_description(VarlinkServer *s) {
        return (s ? s->description : NULL) ?: "varlink";
}

static void varlink_set_state(Varlink *v, VarlinkState state) {
        assert(v);
        assert(state >= 0 && state < _VARLINK_STATE_MAX);

        if (v->state < 0)
                varlink_log(v, "Setting state %s",
                            varlink_state_to_string(state));
        else
                varlink_log(v, "Changing state %s → %s",
                            varlink_state_to_string(v->state),
                            varlink_state_to_string(state));

        v->state = state;
}

static int varlink_new(Varlink **ret) {
        Varlink *v;

        assert(ret);

        v = new(Varlink, 1);
        if (!v)
                return -ENOMEM;

        *v = (Varlink) {
                .n_ref = 1,
                .fd = -1,

                .state = _VARLINK_STATE_INVALID,

                .ucred.uid = UID_INVALID,
                .ucred.gid = GID_INVALID,

                .timestamp = USEC_INFINITY,
                .timeout = VARLINK_DEFAULT_TIMEOUT_USEC
        };

        *ret = v;
        return 0;
}

int varlink_connect_address(Varlink **ret, const char *address) {
        _cleanup_(varlink_unrefp) Varlink *v = NULL;
        union sockaddr_union sockaddr;
        socklen_t sockaddr_len;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(address, -EINVAL);

        r = sockaddr_un_set_path(&sockaddr.un, address);
        if (r < 0)
                return log_debug_errno(r, "Failed to set socket address '%s': %m", address);
        sockaddr_len = r;

        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (v->fd < 0)
                return log_debug_errno(errno, "Failed to create AF_UNIX socket: %m");

        v->fd = fd_move_above_stdio(v->fd);

        if (connect(v->fd, &sockaddr.sa, sockaddr_len) < 0) {
                if (!IN_SET(errno, EAGAIN, EINPROGRESS))
                        return log_debug_errno(errno, "Failed to connect to %s: %m", address);

                v->connecting = true; /* We are asynchronously connecting, i.e. the connect() is being
                                       * processed in the background. As long as that's the case the socket
                                       * is in a special state: it's there, we can poll it for EPOLLOUT, but
                                       * if we attempt to write() to it before we see EPOLLOUT we'll get
                                       * ENOTCONN (and not EAGAIN, like we would for a normal connected
                                       * socket that isn't writable at the moment). Since ENOTCONN on write()
                                       * hence can mean two different things (i.e. connection not complete
                                       * yet vs. already disconnected again), we store as a boolean whether
                                       * we are still in connect(). */
        }

        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        *ret = TAKE_PTR(v);
        return 0;
}

int varlink_connect_fd(Varlink **ret, int fd) {
        Varlink *v;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make fd %d nonblocking: %m", fd);

        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->fd = fd;
        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        /* Note that if this function is called we assume the passed socket (if it is one) is already
         * properly connected, i.e. any asynchronous connect() done on it already completed. Because of that
         * we'll not set the 'connecting' boolean here, i.e. we don't need to avoid write()ing to the socket
         * until the connection is fully set up. Behaviour here is hence a bit different from
         * varlink_connect_address() above, as there we do handle asynchronous connections ourselves and
         * avoid doing write() on it before we saw EPOLLOUT for the first time. */

        *ret = v;
        return 0;
}

static void varlink_detach_event_sources(Varlink *v) {
        assert(v);

        v->io_event_source = sd_event_source_disable_unref(v->io_event_source);
        v->time_event_source = sd_event_source_disable_unref(v->time_event_source);
        v->quit_event_source = sd_event_source_disable_unref(v->quit_event_source);
        v->defer_event_source = sd_event_source_disable_unref(v->defer_event_source);
}

static void varlink_clear(Varlink *v) {
        assert(v);

        varlink_detach_event_sources(v);

        v->fd = safe_close(v->fd);

        v->input_buffer = mfree(v->input_buffer);
        v->output_buffer = mfree(v->output_buffer);

        v->current = json_variant_unref(v->current);
        v->reply = json_variant_unref(v->reply);

        v->event = sd_event_unref(v->event);
}

static Varlink* varlink_destroy(Varlink *v) {
        if (!v)
                return NULL;

        /* If this is called the server object must already been unreffed here. Why that? because when we
         * linked up the varlink connection with the server object we took one ref in each direction */
        assert(!v->server);

        varlink_clear(v);

        free(v->description);
        return mfree(v);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Varlink, varlink, varlink_destroy);

static int varlink_test_disconnect(Varlink *v) {
        assert(v);

        /* Tests whether we the connection has been terminated. We are careful to not stop processing it
         * prematurely, since we want to handle half-open connections as well as possible and want to flush
         * out and read data before we close down if we can. */

        /* Already disconnected? */
        if (!VARLINK_STATE_IS_ALIVE(v->state))
                return 0;

        /* Wait until connection setup is complete, i.e. until asynchronous connect() completes */
        if (v->connecting)
                return 0;

        /* Still something to write and we can write? Stay around */
        if (v->output_buffer_size > 0 && !v->write_disconnected)
                return 0;

        /* Both sides gone already? Then there's no need to stick around */
        if (v->read_disconnected && v->write_disconnected)
                goto disconnect;

        /* If we are waiting for incoming data but the read side is shut down, disconnect. */
        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_IDLE_SERVER) && v->read_disconnected)
                goto disconnect;

        /* Similar, if are a client that hasn't written anything yet but the write side is dead, also
         * disconnect. We also explicitly check for POLLHUP here since we likely won't notice the write side
         * being down if we never wrote anything. */
        if (IN_SET(v->state, VARLINK_IDLE_CLIENT) && (v->write_disconnected || v->got_pollhup))
                goto disconnect;

        /* The server is still expecting to write more, but its write end is disconnected and it got a POLLHUP
         * (i.e. from a disconnected client), so disconnect. */
        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE) && v->write_disconnected && v->got_pollhup)
                goto disconnect;

        return 0;

disconnect:
        varlink_set_state(v, VARLINK_PENDING_DISCONNECT);
        return 1;
}

static int varlink_write(Varlink *v) {
        ssize_t n;

        assert(v);

        if (!VARLINK_STATE_IS_ALIVE(v->state))
                return 0;
        if (v->connecting) /* Writing while we are still wait for a non-blocking connect() to complete will
                            * result in ENOTCONN, hence exit early here */
                return 0;
        if (v->output_buffer_size == 0)
                return 0;
        if (v->write_disconnected)
                return 0;

        assert(v->fd >= 0);

        /* We generally prefer recv()/send() (mostly because of MSG_NOSIGNAL) but also want to be compatible
         * with non-socket IO, hence fall back automatically.
         *
         * Use a local variable to help gcc figure out that we set 'n' in all cases. */
        bool prefer_write = v->prefer_read_write;
        if (!prefer_write) {
                n = send(v->fd, v->output_buffer + v->output_buffer_index, v->output_buffer_size, MSG_DONTWAIT|MSG_NOSIGNAL);
                if (n < 0 && errno == ENOTSOCK)
                        prefer_write = v->prefer_read_write = true;
        }
        if (prefer_write)
                n = write(v->fd, v->output_buffer + v->output_buffer_index, v->output_buffer_size);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        /* If we get informed about a disconnect on write, then let's remember that, but not
                         * act on it just yet. Let's wait for read() to report the issue first. */
                        v->write_disconnected = true;
                        return 1;
                }

                return -errno;
        }

        v->output_buffer_size -= n;

        if (v->output_buffer_size == 0)
                v->output_buffer_index = 0;
        else
                v->output_buffer_index += n;

        v->timestamp = now(CLOCK_MONOTONIC);
        return 1;
}

static int varlink_read(Varlink *v) {
        size_t rs;
        ssize_t n;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_IDLE_SERVER))
                return 0;
        if (v->connecting) /* read() on a socket while we are in connect() will fail with EINVAL, hence exit early here */
                return 0;
        if (v->current)
                return 0;
        if (v->input_buffer_unscanned > 0)
                return 0;
        if (v->read_disconnected)
                return 0;

        if (v->input_buffer_size >= VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        assert(v->fd >= 0);

        if (MALLOC_SIZEOF_SAFE(v->input_buffer) <= v->input_buffer_index + v->input_buffer_size) {
                size_t add;

                add = MIN(VARLINK_BUFFER_MAX - v->input_buffer_size, VARLINK_READ_SIZE);

                if (v->input_buffer_index == 0) {

                        if (!GREEDY_REALLOC(v->input_buffer, v->input_buffer_size + add))
                                return -ENOMEM;

                } else {
                        char *b;

                        b = new(char, v->input_buffer_size + add);
                        if (!b)
                                return -ENOMEM;

                        memcpy(b, v->input_buffer + v->input_buffer_index, v->input_buffer_size);

                        free_and_replace(v->input_buffer, b);
                        v->input_buffer_index = 0;
                }
        }

        rs = MALLOC_SIZEOF_SAFE(v->input_buffer) - (v->input_buffer_index + v->input_buffer_size);

        bool prefer_read = v->prefer_read_write;
        if (!prefer_read) {
                n = recv(v->fd, v->input_buffer + v->input_buffer_index + v->input_buffer_size, rs, MSG_DONTWAIT);
                if (n < 0 && errno == ENOTSOCK)
                        prefer_read = v->prefer_read_write = true;
        }
        if (prefer_read)
                n = read(v->fd, v->input_buffer + v->input_buffer_index + v->input_buffer_size, rs);
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        v->read_disconnected = true;
                        return 1;
                }

                return -errno;
        }
        if (n == 0) { /* EOF */
                v->read_disconnected = true;
                return 1;
        }

        v->input_buffer_size += n;
        v->input_buffer_unscanned += n;

        return 1;
}

static int varlink_parse_message(Varlink *v) {
        const char *e, *begin;
        size_t sz;
        int r;

        assert(v);

        if (v->current)
                return 0;
        if (v->input_buffer_unscanned <= 0)
                return 0;

        assert(v->input_buffer_unscanned <= v->input_buffer_size);
        assert(v->input_buffer_index + v->input_buffer_size <= MALLOC_SIZEOF_SAFE(v->input_buffer));

        begin = v->input_buffer + v->input_buffer_index;

        e = memchr(begin + v->input_buffer_size - v->input_buffer_unscanned, 0, v->input_buffer_unscanned);
        if (!e) {
                v->input_buffer_unscanned = 0;
                return 0;
        }

        sz = e - begin + 1;

        varlink_log(v, "New incoming message: %s", begin); /* FIXME: should we output the whole message here before validation?
                                                            * This may produce a non-printable journal entry if the message
                                                            * is invalid. We may also expose privileged information. */

        r = json_parse(begin, 0, &v->current, NULL, NULL);
        if (r < 0) {
                /* If we encounter a parse failure flush all data. We cannot possibly recover from this,
                 * hence drop all buffered data now. */
                v->input_buffer_index = v->input_buffer_size = v->input_buffer_unscanned = 0;
                return varlink_log_errno(v, r, "Failed to parse JSON: %m");
        }

        v->input_buffer_size -= sz;

        if (v->input_buffer_size == 0)
                v->input_buffer_index = 0;
        else
                v->input_buffer_index += sz;

        v->input_buffer_unscanned = v->input_buffer_size;
        return 1;
}

static int varlink_test_timeout(Varlink *v) {
        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING))
                return 0;
        if (v->timeout == USEC_INFINITY)
                return 0;

        if (now(CLOCK_MONOTONIC) < usec_add(v->timestamp, v->timeout))
                return 0;

        varlink_set_state(v, VARLINK_PENDING_TIMEOUT);

        return 1;
}

static int varlink_dispatch_local_error(Varlink *v, const char *error) {
        int r;

        assert(v);
        assert(error);

        if (!v->reply_callback)
                return 0;

        r = v->reply_callback(v, NULL, error, VARLINK_REPLY_ERROR|VARLINK_REPLY_LOCAL, v->userdata);
        if (r < 0)
                log_debug_errno(r, "Reply callback returned error, ignoring: %m");

        return 1;
}

static int varlink_dispatch_timeout(Varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_TIMEOUT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_TIMEOUT);
        varlink_dispatch_local_error(v, VARLINK_ERROR_TIMEOUT);
        varlink_close(v);

        return 1;
}

static int varlink_dispatch_disconnect(Varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_DISCONNECT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_DISCONNECT);
        varlink_dispatch_local_error(v, VARLINK_ERROR_DISCONNECTED);
        varlink_close(v);

        return 1;
}

static int varlink_sanitize_parameters(JsonVariant **v) {
        assert(v);

        /* Varlink always wants a parameters list, hence make one if the caller doesn't want any */
        if (!*v)
                return json_variant_new_object(v, NULL, 0);
        else if (!json_variant_is_object(*v))
                return -EINVAL;

        return 0;
}

static int varlink_dispatch_reply(Varlink *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        VarlinkReplyFlags flags = 0;
        const char *error = NULL;
        JsonVariant *e;
        const char *k;
        int r;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING))
                return 0;
        if (!v->current)
                return 0;

        assert(v->n_pending > 0);

        if (!json_variant_is_object(v->current))
                goto invalid;

        JSON_VARIANT_OBJECT_FOREACH(k, e, v->current) {

                if (streq(k, "error")) {
                        if (error)
                                goto invalid;
                        if (!json_variant_is_string(e))
                                goto invalid;

                        error = json_variant_string(e);
                        flags |= VARLINK_REPLY_ERROR;

                } else if (streq(k, "parameters")) {
                        if (parameters)
                                goto invalid;
                        if (!json_variant_is_object(e))
                                goto invalid;

                        parameters = json_variant_ref(e);

                } else if (streq(k, "continues")) {
                        if (FLAGS_SET(flags, VARLINK_REPLY_CONTINUES))
                                goto invalid;

                        if (!json_variant_is_boolean(e))
                                goto invalid;

                        if (json_variant_boolean(e))
                                flags |= VARLINK_REPLY_CONTINUES;
                } else
                        goto invalid;
        }

        /* Replies with 'continue' set are only OK if we set 'more' when the method call was initiated */
        if (v->state != VARLINK_AWAITING_REPLY_MORE && FLAGS_SET(flags, VARLINK_REPLY_CONTINUES))
                goto invalid;

        /* An error is final */
        if (error && FLAGS_SET(flags, VARLINK_REPLY_CONTINUES))
                goto invalid;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                goto invalid;

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE)) {
                varlink_set_state(v, VARLINK_PROCESSING_REPLY);

                if (v->reply_callback) {
                        r = v->reply_callback(v, parameters, error, flags, v->userdata);
                        if (r < 0)
                                log_debug_errno(r, "Reply callback returned error, ignoring: %m");
                }

                v->current = json_variant_unref(v->current);

                if (v->state == VARLINK_PROCESSING_REPLY) {

                        assert(v->n_pending > 0);

                        if (!FLAGS_SET(flags, VARLINK_REPLY_CONTINUES))
                                v->n_pending--;

                        varlink_set_state(v,
                                          FLAGS_SET(flags, VARLINK_REPLY_CONTINUES) ? VARLINK_AWAITING_REPLY_MORE :
                                          v->n_pending == 0 ? VARLINK_IDLE_CLIENT : VARLINK_AWAITING_REPLY);
                }
        } else {
                assert(v->state == VARLINK_CALLING);
                varlink_set_state(v, VARLINK_CALLED);
        }

        return 1;

invalid:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, VARLINK_ERROR_PROTOCOL);
        varlink_close(v);

        return 1;
}

static int varlink_dispatch_method(Varlink *v) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        VarlinkMethodFlags flags = 0;
        const char *method = NULL, *error;
        JsonVariant *e;
        VarlinkMethod callback;
        const char *k;
        int r;

        assert(v);

        if (v->state != VARLINK_IDLE_SERVER)
                return 0;
        if (!v->current)
                return 0;

        if (!json_variant_is_object(v->current))
                goto invalid;

        JSON_VARIANT_OBJECT_FOREACH(k, e, v->current) {

                if (streq(k, "method")) {
                        if (method)
                                goto invalid;
                        if (!json_variant_is_string(e))
                                goto invalid;

                        method = json_variant_string(e);

                } else if (streq(k, "parameters")) {
                        if (parameters)
                                goto invalid;
                        if (!json_variant_is_object(e))
                                goto invalid;

                        parameters = json_variant_ref(e);

                } else if (streq(k, "oneway")) {

                        if ((flags & (VARLINK_METHOD_ONEWAY|VARLINK_METHOD_MORE)) != 0)
                                goto invalid;

                        if (!json_variant_is_boolean(e))
                                goto invalid;

                        if (json_variant_boolean(e))
                                flags |= VARLINK_METHOD_ONEWAY;

                } else if (streq(k, "more")) {

                        if ((flags & (VARLINK_METHOD_ONEWAY|VARLINK_METHOD_MORE)) != 0)
                                goto invalid;

                        if (!json_variant_is_boolean(e))
                                goto invalid;

                        if (json_variant_boolean(e))
                                flags |= VARLINK_METHOD_MORE;

                } else
                        goto invalid;
        }

        if (!method)
                goto invalid;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                goto fail;

        varlink_set_state(v, (flags & VARLINK_METHOD_MORE)   ? VARLINK_PROCESSING_METHOD_MORE :
                             (flags & VARLINK_METHOD_ONEWAY) ? VARLINK_PROCESSING_METHOD_ONEWAY :
                                                               VARLINK_PROCESSING_METHOD);

        assert(v->server);

        if (STR_IN_SET(method, "org.varlink.service.GetInfo", "org.varlink.service.GetInterface")) {
                /* For now, we don't implement a single of varlink's own methods */
                callback = NULL;
                error = VARLINK_ERROR_METHOD_NOT_IMPLEMENTED;
        } else if (startswith(method, "org.varlink.service.")) {
                callback = NULL;
                error = VARLINK_ERROR_METHOD_NOT_FOUND;
        } else {
                callback = hashmap_get(v->server->methods, method);
                error = VARLINK_ERROR_METHOD_NOT_FOUND;
        }

        if (callback) {
                r = callback(v, parameters, flags, v->userdata);
                if (r < 0) {
                        log_debug_errno(r, "Callback for %s returned error: %m", method);

                        /* We got an error back from the callback. Propagate it to the client if the method call remains unanswered. */
                        if (!FLAGS_SET(flags, VARLINK_METHOD_ONEWAY)) {
                                r = varlink_error_errno(v, r);
                                if (r < 0)
                                        return r;
                        }
                }
        } else if (!FLAGS_SET(flags, VARLINK_METHOD_ONEWAY)) {
                assert(error);

                r = varlink_errorb(v, error, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method))));
                if (r < 0)
                        return r;
        }

        switch (v->state) {

        case VARLINK_PROCESSED_METHOD: /* Method call is fully processed */
        case VARLINK_PROCESSING_METHOD_ONEWAY: /* ditto */
                v->current = json_variant_unref(v->current);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
                break;

        case VARLINK_PROCESSING_METHOD: /* Method call wasn't replied to, will be replied to later */
                varlink_set_state(v, VARLINK_PENDING_METHOD);
                break;

        case VARLINK_PROCESSING_METHOD_MORE: /* No reply for a "more" message was sent, more to come */
                varlink_set_state(v, VARLINK_PENDING_METHOD_MORE);
                break;

        default:
                assert_not_reached("Unexpected state");

        }

        return r;

invalid:
        r = -EINVAL;

fail:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, VARLINK_ERROR_PROTOCOL);
        varlink_close(v);

        return r;
}

int varlink_process(Varlink *v) {
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        varlink_ref(v);

        r = varlink_write(v);
        if (r < 0)
                varlink_log_errno(v, r, "Write failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_dispatch_reply(v);
        if (r < 0)
                varlink_log_errno(v, r, "Reply dispatch failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_dispatch_method(v);
        if (r < 0)
                varlink_log_errno(v, r, "Method dispatch failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_parse_message(v);
        if (r < 0)
                varlink_log_errno(v, r, "Message parsing failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_read(v);
        if (r < 0)
                varlink_log_errno(v, r, "Read failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_test_disconnect(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_disconnect(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_test_timeout(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_timeout(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

finish:
        if (r >= 0 && v->defer_event_source) {
                int q;

                /* If we did some processing, make sure we are called again soon */
                q = sd_event_source_set_enabled(v->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0)
                        r = varlink_log_errno(v, q, "Failed to enable deferred event source: %m");
        }

        if (r < 0) {
                if (VARLINK_STATE_IS_ALIVE(v->state))
                        /* Initiate disconnection */
                        varlink_set_state(v, VARLINK_PENDING_DISCONNECT);
                else
                        /* We failed while disconnecting, in that case close right away */
                        varlink_close(v);
        }

        varlink_unref(v);
        return r;
}

static void handle_revents(Varlink *v, int revents) {
        assert(v);

        if (v->connecting) {
                /* If we have seen POLLOUT or POLLHUP on a socket we are asynchronously waiting a connect()
                 * to complete on, we know we are ready. We don't read the connection error here though,
                 * we'll get the error on the next read() or write(). */
                if ((revents & (POLLOUT|POLLHUP)) == 0)
                        return;

                varlink_log(v, "Anynchronous connection completed.");
                v->connecting = false;
        } else {
                /* Note that we don't care much about POLLIN/POLLOUT here, we'll just try reading and writing
                 * what we can. However, we do care about POLLHUP to detect connection termination even if we
                 * momentarily don't want to read nor write anything. */

                if (!FLAGS_SET(revents, POLLHUP))
                        return;

                varlink_log(v, "Got POLLHUP from socket.");
                v->got_pollhup = true;
        }
}

int varlink_wait(Varlink *v, usec_t timeout) {
        int r, fd, events;
        usec_t t;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        r = varlink_get_timeout(v, &t);
        if (r < 0)
                return r;
        if (t != USEC_INFINITY) {
                usec_t n;

                n = now(CLOCK_MONOTONIC);
                if (t < n)
                        t = 0;
                else
                        t = usec_sub_unsigned(t, n);
        }

        if (timeout != USEC_INFINITY &&
            (t == USEC_INFINITY || timeout < t))
                t = timeout;

        fd = varlink_get_fd(v);
        if (fd < 0)
                return fd;

        events = varlink_get_events(v);
        if (events < 0)
                return events;

        r = fd_wait_for_event(fd, events, t);
        if (r <= 0)
                return r;

        handle_revents(v, r);
        return 1;
}

int varlink_get_fd(Varlink *v) {

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->fd < 0)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBADF), "No valid fd.");

        return v->fd;
}

int varlink_get_events(Varlink *v) {
        int ret = 0;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        if (v->connecting) /* When processing an asynchronous connect(), we only wait for EPOLLOUT, which
                            * tells us that the connection is now complete. Before that we should neither
                            * write() or read() from the fd. */
                return EPOLLOUT;

        if (!v->read_disconnected &&
            IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_IDLE_SERVER) &&
            !v->current &&
            v->input_buffer_unscanned <= 0)
                ret |= EPOLLIN;

        if (!v->write_disconnected &&
            v->output_buffer_size > 0)
                ret |= EPOLLOUT;

        return ret;
}

int varlink_get_timeout(Varlink *v, usec_t *ret) {
        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING) &&
            v->timeout != USEC_INFINITY) {
                if (ret)
                        *ret = usec_add(v->timestamp, v->timeout);
                return 1;
        } else {
                if (ret)
                        *ret = USEC_INFINITY;
                return 0;
        }
}

int varlink_flush(Varlink *v) {
        int ret = 0, r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        for (;;) {
                if (v->output_buffer_size == 0)
                        break;
                if (v->write_disconnected)
                        return -ECONNRESET;

                r = varlink_write(v);
                if (r < 0)
                        return r;
                if (r > 0) {
                        ret = 1;
                        continue;
                }

                r = fd_wait_for_event(v->fd, POLLOUT, USEC_INFINITY);
                if (r < 0)
                        return varlink_log_errno(v, r, "Poll failed on fd: %m");

                assert(r != 0);

                handle_revents(v, r);
        }

        return ret;
}

static void varlink_detach_server(Varlink *v) {
        VarlinkServer *saved_server;
        assert(v);

        if (!v->server)
                return;

        if (v->server->by_uid &&
            v->ucred_acquired &&
            uid_is_valid(v->ucred.uid)) {
                unsigned c;

                c = PTR_TO_UINT(hashmap_get(v->server->by_uid, UID_TO_PTR(v->ucred.uid)));
                assert(c > 0);

                if (c == 1)
                        (void) hashmap_remove(v->server->by_uid, UID_TO_PTR(v->ucred.uid));
                else
                        (void) hashmap_replace(v->server->by_uid, UID_TO_PTR(v->ucred.uid), UINT_TO_PTR(c - 1));
        }

        assert(v->server->n_connections > 0);
        v->server->n_connections--;

        /* If this is a connection associated to a server, then let's disconnect the server and the
         * connection from each other. This drops the dangling reference that connect_callback() set up. But
         * before we release the references, let's call the disconnection callback if it is defined. */

        saved_server = TAKE_PTR(v->server);

        if (saved_server->disconnect_callback)
                saved_server->disconnect_callback(saved_server, v, saved_server->userdata);

        varlink_server_unref(saved_server);
        varlink_unref(v);
}

int varlink_close(Varlink *v) {
        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return 0;

        varlink_set_state(v, VARLINK_DISCONNECTED);

        /* Let's take a reference first, since varlink_detach_server() might drop the final (dangling) ref
         * which would destroy us before we can call varlink_clear() */
        varlink_ref(v);
        varlink_detach_server(v);
        varlink_clear(v);
        varlink_unref(v);

        return 1;
}

Varlink* varlink_close_unref(Varlink *v) {
        if (!v)
                return NULL;

        (void) varlink_close(v);
        return varlink_unref(v);
}

Varlink* varlink_flush_close_unref(Varlink *v) {
        if (!v)
                return NULL;

        (void) varlink_flush(v);
        return varlink_close_unref(v);
}

static int varlink_enqueue_json(Varlink *v, JsonVariant *m) {
        _cleanup_free_ char *text = NULL;
        int r;

        assert(v);
        assert(m);

        r = json_variant_format(m, 0, &text);
        if (r < 0)
                return r;
        assert(text[r] == '\0');

        if (v->output_buffer_size + r + 1 > VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        varlink_log(v, "Sending message: %s", text);

        if (v->output_buffer_size == 0) {

                free_and_replace(v->output_buffer, text);

                v->output_buffer_size = r + 1;
                v->output_buffer_index = 0;

        } else if (v->output_buffer_index == 0) {

                if (!GREEDY_REALLOC(v->output_buffer, v->output_buffer_size + r + 1))
                        return -ENOMEM;

                memcpy(v->output_buffer + v->output_buffer_size, text, r + 1);
                v->output_buffer_size += r + 1;

        } else {
                char *n;
                const size_t new_size = v->output_buffer_size + r + 1;

                n = new(char, new_size);
                if (!n)
                        return -ENOMEM;

                memcpy(mempcpy(n, v->output_buffer + v->output_buffer_index, v->output_buffer_size), text, r + 1);

                free_and_replace(v->output_buffer, n);
                v->output_buffer_size = new_size;
                v->output_buffer_index = 0;
        }

        return 0;
}

int varlink_send(Varlink *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* We allow enqueuing multiple method calls at once! */
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters)),
                                       JSON_BUILD_PAIR("oneway", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        /* No state change here, this is one-way only after all */
        v->timestamp = now(CLOCK_MONOTONIC);
        return 0;
}

int varlink_sendb(Varlink *v, const char *method, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_send(v, method, parameters);
}

int varlink_invoke(Varlink *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* We allow enqueuing multiple method calls at once! */
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_AWAITING_REPLY);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        return 0;
}

int varlink_invokeb(Varlink *v, const char *method, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_invoke(v, method, parameters);
}

int varlink_observe(Varlink *v, const char *method, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* Note that we don't allow enqueuing multiple method calls when we are in more/continues mode! We
         * thus insist on an idle client here. */
        if (v->state != VARLINK_IDLE_CLIENT)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters)),
                                       JSON_BUILD_PAIR("more", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_AWAITING_REPLY_MORE);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        return 0;
}

int varlink_observeb(Varlink *v, const char *method, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_observe(v, method, parameters);
}

int varlink_call(
                Varlink *v,
                const char *method,
                JsonVariant *parameters,
                JsonVariant **ret_parameters,
                const char **ret_error_id,
                VarlinkReplyFlags *ret_flags) {

        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        assert(v->n_pending == 0); /* n_pending can't be > 0 if we are in VARLINK_IDLE_CLIENT state */

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("method", JSON_BUILD_STRING(method)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_CALLING);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        while (v->state == VARLINK_CALLING) {

                r = varlink_process(v);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = varlink_wait(v, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        switch (v->state) {

        case VARLINK_CALLED:
                assert(v->current);

                json_variant_unref(v->reply);
                v->reply = TAKE_PTR(v->current);

                varlink_set_state(v, VARLINK_IDLE_CLIENT);
                assert(v->n_pending == 1);
                v->n_pending--;

                if (ret_parameters)
                        *ret_parameters = json_variant_by_key(v->reply, "parameters");
                if (ret_error_id)
                        *ret_error_id = json_variant_string(json_variant_by_key(v->reply, "error"));
                if (ret_flags)
                        *ret_flags = 0;

                return 1;

        case VARLINK_PENDING_DISCONNECT:
        case VARLINK_DISCONNECTED:
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ECONNRESET), "Connection was closed.");

        case VARLINK_PENDING_TIMEOUT:
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ETIME), "Connection timed out.");

        default:
                assert_not_reached("Unexpected state after method call.");
        }
}

int varlink_callb(
                Varlink *v,
                const char *method,
                JsonVariant **ret_parameters,
                const char **ret_error_id,
                VarlinkReplyFlags *ret_flags, ...) {

        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, ret_flags);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_call(v, method, parameters, ret_parameters, ret_error_id, ret_flags);
}

int varlink_reply(Varlink *v, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return -ENOTCONN;
        if (!IN_SET(v->state,
                    VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE,
                    VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE))
                return -EBUSY;

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE)) {
                /* We just replied to a method call that was let hanging for a while (i.e. we were outside of
                 * the varlink_dispatch_method() stack frame), which means with this reply we are ready to
                 * process further messages. */
                v->current = json_variant_unref(v->current);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
        } else
                /* We replied to a method call from within the varlink_dispatch_method() stack frame), which
                 * means we should it handle the rest of the state engine. */
                varlink_set_state(v, VARLINK_PROCESSED_METHOD);

        return 1;
}

int varlink_replyb(Varlink *v, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, v);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return r;

        return varlink_reply(v, parameters);
}

int varlink_error(Varlink *v, const char *error_id, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(error_id, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (!IN_SET(v->state,
                    VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE,
                    VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("error", JSON_BUILD_STRING(error_id)),
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE)) {
                v->current = json_variant_unref(v->current);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
        } else
                varlink_set_state(v, VARLINK_PROCESSED_METHOD);

        return 1;
}

int varlink_errorb(Varlink *v, const char *error_id, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);
        assert_return(error_id, -EINVAL);

        va_start(ap, error_id);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_error(v, error_id, parameters);
}

int varlink_error_invalid_parameter(Varlink *v, JsonVariant *parameters) {

        assert_return(v, -EINVAL);
        assert_return(parameters, -EINVAL);

        /* We expect to be called in one of two ways: the 'parameters' argument is a string variant in which
         * case it is the parameter key name that is invalid. Or the 'parameters' argument is an object
         * variant in which case we'll pull out the first key. The latter mode is useful in functions that
         * don't expect any arguments. */

        if (json_variant_is_string(parameters))
                return varlink_error(v, VARLINK_ERROR_INVALID_PARAMETER, parameters);

        if (json_variant_is_object(parameters) &&
            json_variant_elements(parameters) > 0)
                return varlink_error(v, VARLINK_ERROR_INVALID_PARAMETER,
                                     json_variant_by_index(parameters, 0));

        return -EINVAL;
}

int varlink_error_errno(Varlink *v, int error) {
        return varlink_errorb(
                        v,
                        VARLINK_ERROR_SYSTEM,
                        JSON_BUILD_OBJECT(JSON_BUILD_PAIR("errno", JSON_BUILD_INTEGER(abs(error)))));
}

int varlink_notify(Varlink *v, JsonVariant *parameters) {
        _cleanup_(json_variant_unrefp) JsonVariant *m = NULL;
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (!IN_SET(v->state, VARLINK_PROCESSING_METHOD_MORE, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = varlink_sanitize_parameters(&parameters);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to sanitize parameters: %m");

        r = json_build(&m, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("parameters", JSON_BUILD_VARIANT(parameters)),
                                       JSON_BUILD_PAIR("continues", JSON_BUILD_BOOLEAN(true))));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        /* No state change, as more is coming */
        return 1;
}

int varlink_notifyb(Varlink *v, ...) {
        _cleanup_(json_variant_unrefp) JsonVariant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, v);
        r = json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return varlink_notify(v, parameters);
}

int varlink_bind_reply(Varlink *v, VarlinkReply callback) {
        assert_return(v, -EINVAL);

        if (callback && v->reply_callback && callback != v->reply_callback)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        v->reply_callback = callback;

        return 0;
}

void* varlink_set_userdata(Varlink *v, void *userdata) {
        void *old;

        assert_return(v, NULL);

        old = v->userdata;
        v->userdata = userdata;

        return old;
}

void* varlink_get_userdata(Varlink *v) {
        assert_return(v, NULL);

        return v->userdata;
}

static int varlink_acquire_ucred(Varlink *v) {
        int r;

        assert(v);

        if (v->ucred_acquired)
                return 0;

        r = getpeercred(v->fd, &v->ucred);
        if (r < 0)
                return r;

        v->ucred_acquired = true;
        return 0;
}

int varlink_get_peer_uid(Varlink *v, uid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to acquire credentials: %m");

        if (!uid_is_valid(v->ucred.uid))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENODATA), "Peer uid is invalid.");

        *ret = v->ucred.uid;
        return 0;
}

int varlink_get_peer_pid(Varlink *v, pid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to acquire credentials: %m");

        if (!pid_is_valid(v->ucred.pid))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENODATA), "Peer uid is invalid.");

        *ret = v->ucred.pid;
        return 0;
}

int varlink_set_relative_timeout(Varlink *v, usec_t timeout) {
        assert_return(v, -EINVAL);
        assert_return(timeout > 0, -EINVAL);

        v->timeout = timeout;
        return 0;
}

VarlinkServer *varlink_get_server(Varlink *v) {
        assert_return(v, NULL);

        return v->server;
}

int varlink_set_description(Varlink *v, const char *description) {
        assert_return(v, -EINVAL);

        return free_and_strdup(&v->description, description);
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Varlink *v = userdata;

        assert(s);
        assert(v);

        handle_revents(v, revents);
        (void) varlink_process(v);

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        Varlink *v = userdata;

        assert(s);
        assert(v);

        (void) varlink_process(v);
        return 1;
}

static int defer_callback(sd_event_source *s, void *userdata) {
        Varlink *v = userdata;

        assert(s);
        assert(v);

        (void) varlink_process(v);
        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        Varlink *v = userdata;
        int r, e;
        usec_t until;
        bool have_timeout;

        assert(s);
        assert(v);

        e = varlink_get_events(v);
        if (e < 0)
                return e;

        r = sd_event_source_set_io_events(v->io_event_source, e);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to set source events: %m");

        r = varlink_get_timeout(v, &until);
        if (r < 0)
                return r;
        have_timeout = r > 0;

        if (have_timeout) {
                r = sd_event_source_set_time(v->time_event_source, until);
                if (r < 0)
                        return varlink_log_errno(v, r, "Failed to set source time: %m");
        }

        r = sd_event_source_set_enabled(v->time_event_source, have_timeout ? SD_EVENT_ON : SD_EVENT_OFF);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enable event source: %m");

        return 1;
}

static int quit_callback(sd_event_source *event, void *userdata) {
        Varlink *v = userdata;

        assert(event);
        assert(v);

        varlink_flush(v);
        varlink_close(v);

        return 1;
}

int varlink_attach_event(Varlink *v, sd_event *e, int64_t priority) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(!v->event, -EBUSY);

        if (e)
                v->event = sd_event_ref(e);
        else {
                r = sd_event_default(&v->event);
                if (r < 0)
                        return varlink_log_errno(v, r, "Failed to create event source: %m");
        }

        r = sd_event_add_time(v->event, &v->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->time_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->time_event_source, "varlink-time");

        r = sd_event_add_exit(v->event, &v->quit_event_source, quit_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->quit_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->quit_event_source, "varlink-quit");

        r = sd_event_add_io(v->event, &v->io_event_source, v->fd, 0, io_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(v->io_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->io_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->io_event_source, "varlink-io");

        r = sd_event_add_defer(v->event, &v->defer_event_source, defer_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->defer_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->defer_event_source, "varlink-defer");

        return 0;

fail:
        varlink_log_errno(v, r, "Failed to setup event source: %m");
        varlink_detach_event(v);
        return r;
}

void varlink_detach_event(Varlink *v) {
        if (!v)
                return;

        varlink_detach_event_sources(v);

        v->event = sd_event_unref(v->event);
}

sd_event *varlink_get_event(Varlink *v) {
        assert_return(v, NULL);

        return v->event;
}

int varlink_server_new(VarlinkServer **ret, VarlinkServerFlags flags) {
        VarlinkServer *s;

        assert_return(ret, -EINVAL);
        assert_return((flags & ~_VARLINK_SERVER_FLAGS_ALL) == 0, -EINVAL);

        s = new(VarlinkServer, 1);
        if (!s)
                return log_oom_debug();

        *s = (VarlinkServer) {
                .n_ref = 1,
                .flags = flags,
                .connections_max = varlink_server_connections_max(NULL),
                .connections_per_uid_max = varlink_server_connections_per_uid_max(NULL),
        };

        *ret = s;
        return 0;
}

static VarlinkServer* varlink_server_destroy(VarlinkServer *s) {
        char *m;

        if (!s)
                return NULL;

        varlink_server_shutdown(s);

        while ((m = hashmap_steal_first_key(s->methods)))
                free(m);

        hashmap_free(s->methods);
        hashmap_free(s->by_uid);

        sd_event_unref(s->event);

        free(s->description);

        return mfree(s);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(VarlinkServer, varlink_server, varlink_server_destroy);

static int validate_connection(VarlinkServer *server, const struct ucred *ucred) {
        int allowed = -1;

        assert(server);
        assert(ucred);

        if (FLAGS_SET(server->flags, VARLINK_SERVER_ROOT_ONLY))
                allowed = ucred->uid == 0;

        if (FLAGS_SET(server->flags, VARLINK_SERVER_MYSELF_ONLY))
                allowed = allowed > 0 || ucred->uid == getuid();

        if (allowed == 0) { /* Allow access when it is explicitly allowed or when neither
                             * VARLINK_SERVER_ROOT_ONLY nor VARLINK_SERVER_MYSELF_ONLY are specified. */
                varlink_server_log(server, "Unprivileged client attempted connection, refusing.");
                return 0;
        }

        if (server->n_connections >= server->connections_max) {
                varlink_server_log(server, "Connection limit of %u reached, refusing.", server->connections_max);
                return 0;
        }

        if (FLAGS_SET(server->flags, VARLINK_SERVER_ACCOUNT_UID)) {
                unsigned c;

                if (!uid_is_valid(ucred->uid)) {
                        varlink_server_log(server, "Client with invalid UID attempted connection, refusing.");
                        return 0;
                }

                c = PTR_TO_UINT(hashmap_get(server->by_uid, UID_TO_PTR(ucred->uid)));
                if (c >= server->connections_per_uid_max) {
                        varlink_server_log(server, "Per-UID connection limit of %u reached, refusing.",
                                           server->connections_per_uid_max);
                        return 0;
                }
        }

        return 1;
}

static int count_connection(VarlinkServer *server, struct ucred *ucred) {
        unsigned c;
        int r;

        assert(server);
        assert(ucred);

        server->n_connections++;

        if (FLAGS_SET(server->flags, VARLINK_SERVER_ACCOUNT_UID)) {
                r = hashmap_ensure_allocated(&server->by_uid, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate UID hash table: %m");

                c = PTR_TO_UINT(hashmap_get(server->by_uid, UID_TO_PTR(ucred->uid)));

                varlink_server_log(server, "Connections of user " UID_FMT ": %u (of %u max)",
                                   ucred->uid, c, server->connections_per_uid_max);

                r = hashmap_replace(server->by_uid, UID_TO_PTR(ucred->uid), UINT_TO_PTR(c + 1));
                if (r < 0)
                        return log_debug_errno(r, "Failed to increment counter in UID hash table: %m");
        }

        return 0;
}

int varlink_server_add_connection(VarlinkServer *server, int fd, Varlink **ret) {
        _cleanup_(varlink_unrefp) Varlink *v = NULL;
        bool ucred_acquired;
        struct ucred ucred;
        int r;

        assert_return(server, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        if ((server->flags & (VARLINK_SERVER_ROOT_ONLY|VARLINK_SERVER_ACCOUNT_UID)) != 0) {
                r = getpeercred(fd, &ucred);
                if (r < 0)
                        return varlink_server_log_errno(server, r, "Failed to acquire peer credentials of incoming socket, refusing: %m");

                ucred_acquired = true;

                r = validate_connection(server, &ucred);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EPERM;
        } else
                ucred_acquired = false;

        r = varlink_new(&v);
        if (r < 0)
                return varlink_server_log_errno(server, r, "Failed to allocate connection object: %m");

        r = count_connection(server, &ucred);
        if (r < 0)
                return r;

        v->fd = fd;
        if (server->flags & VARLINK_SERVER_INHERIT_USERDATA)
                v->userdata = server->userdata;

        if (ucred_acquired) {
                v->ucred = ucred;
                v->ucred_acquired = true;
        }

        (void) asprintf(&v->description, "%s-%i", server->description ?: "varlink", v->fd);

        /* Link up the server and the connection, and take reference in both directions. Note that the
         * reference on the connection is left dangling. It will be dropped when the connection is closed,
         * which happens in varlink_close(), including in the event loop quit callback. */
        v->server = varlink_server_ref(server);
        varlink_ref(v);

        varlink_set_state(v, VARLINK_IDLE_SERVER);

        if (server->event) {
                r = varlink_attach_event(v, server->event, server->event_priority);
                if (r < 0) {
                        varlink_log_errno(v, r, "Failed to attach new connection: %m");
                        v->fd = -1; /* take the fd out of the connection again */
                        varlink_close(v);
                        return r;
                }
        }

        if (ret)
                *ret = v;

        return 0;
}

static int connect_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        VarlinkServerSocket *ss = userdata;
        _cleanup_close_ int cfd = -1;
        Varlink *v = NULL;
        int r;

        assert(source);
        assert(ss);

        varlink_server_log(ss->server, "New incoming connection.");

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return varlink_server_log_errno(ss->server, errno, "Failed to accept incoming socket: %m");
        }

        r = varlink_server_add_connection(ss->server, cfd, &v);
        if (r < 0)
                return 0;

        TAKE_FD(cfd);

        if (ss->server->connect_callback) {
                r = ss->server->connect_callback(ss->server, v, ss->server->userdata);
                if (r < 0) {
                        varlink_log_errno(v, r, "Connection callback returned error, disconnecting client: %m");
                        varlink_close(v);
                        return 0;
                }
        }

        return 0;
}

int varlink_server_listen_fd(VarlinkServer *s, int fd) {
        _cleanup_free_ VarlinkServerSocket *ss = NULL;
        int r;

        assert_return(s, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        ss = new(VarlinkServerSocket, 1);
        if (!ss)
                return log_oom_debug();

        *ss = (VarlinkServerSocket) {
                .server = s,
                .fd = fd,
        };

        if (s->event) {
                r = sd_event_add_io(s->event, &ss->event_source, fd, EPOLLIN, connect_callback, ss);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(ss->event_source, s->event_priority);
                if (r < 0)
                        return r;
        }

        LIST_PREPEND(sockets, s->sockets, TAKE_PTR(ss));
        return 0;
}

int varlink_server_listen_address(VarlinkServer *s, const char *address, mode_t m) {
        union sockaddr_union sockaddr;
        socklen_t sockaddr_len;
        _cleanup_close_ int fd = -1;
        int r;

        assert_return(s, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return((m & ~0777) == 0, -EINVAL);

        r = sockaddr_un_set_path(&sockaddr.un, address);
        if (r < 0)
                return r;
        sockaddr_len = r;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        fd = fd_move_above_stdio(fd);

        (void) sockaddr_un_unlink(&sockaddr.un);

        RUN_WITH_UMASK(~m & 0777) {
                r = mac_selinux_bind(fd, &sockaddr.sa, sockaddr_len);
                if (r < 0)
                        return r;
        }

        if (listen(fd, SOMAXCONN) < 0)
                return -errno;

        r = varlink_server_listen_fd(s, fd);
        if (r < 0)
                return r;

        TAKE_FD(fd);
        return 0;
}

void* varlink_server_set_userdata(VarlinkServer *s, void *userdata) {
        void *ret;

        assert_return(s, NULL);

        ret = s->userdata;
        s->userdata = userdata;

        return ret;
}

void* varlink_server_get_userdata(VarlinkServer *s) {
        assert_return(s, NULL);

        return s->userdata;
}

static VarlinkServerSocket* varlink_server_socket_destroy(VarlinkServerSocket *ss) {
        if (!ss)
                return NULL;

        if (ss->server)
                LIST_REMOVE(sockets, ss->server->sockets, ss);

        sd_event_source_disable_unref(ss->event_source);

        free(ss->address);
        safe_close(ss->fd);

        return mfree(ss);
}

int varlink_server_shutdown(VarlinkServer *s) {
        assert_return(s, -EINVAL);

        while (s->sockets)
                varlink_server_socket_destroy(s->sockets);

        return 0;
}

int varlink_server_attach_event(VarlinkServer *s, sd_event *e, int64_t priority) {
        VarlinkServerSocket *ss;
        int r;

        assert_return(s, -EINVAL);
        assert_return(!s->event, -EBUSY);

        if (e)
                s->event = sd_event_ref(e);
        else {
                r = sd_event_default(&s->event);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(sockets, ss, s->sockets) {
                assert(!ss->event_source);

                r = sd_event_add_io(s->event, &ss->event_source, ss->fd, EPOLLIN, connect_callback, ss);
                if (r < 0)
                        goto fail;

                r = sd_event_source_set_priority(ss->event_source, priority);
                if (r < 0)
                        goto fail;
        }

        s->event_priority = priority;
        return 0;

fail:
        varlink_server_detach_event(s);
        return r;
}

int varlink_server_detach_event(VarlinkServer *s) {
        VarlinkServerSocket *ss;

        assert_return(s, -EINVAL);

        LIST_FOREACH(sockets, ss, s->sockets) {

                if (!ss->event_source)
                        continue;

                (void) sd_event_source_set_enabled(ss->event_source, SD_EVENT_OFF);
                ss->event_source = sd_event_source_unref(ss->event_source);
        }

        sd_event_unref(s->event);
        return 0;
}

sd_event *varlink_server_get_event(VarlinkServer *s) {
        assert_return(s, NULL);

        return s->event;
}

int varlink_server_bind_method(VarlinkServer *s, const char *method, VarlinkMethod callback) {
        _cleanup_free_ char *m = NULL;
        int r;

        assert_return(s, -EINVAL);
        assert_return(method, -EINVAL);
        assert_return(callback, -EINVAL);

        if (startswith(method, "org.varlink.service."))
                return log_debug_errno(SYNTHETIC_ERRNO(EEXIST), "Cannot bind server to '%s'.", method);

        m = strdup(method);
        if (!m)
                return log_oom_debug();

        r = hashmap_ensure_put(&s->methods, &string_hash_ops, m, callback);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0)
                return log_debug_errno(r, "Failed to register callback: %m");
        if (r > 0)
                TAKE_PTR(m);

        return 0;
}

int varlink_server_bind_method_many_internal(VarlinkServer *s, ...) {
        va_list ap;
        int r = 0;

        assert_return(s, -EINVAL);

        va_start(ap, s);
        for (;;) {
                VarlinkMethod callback;
                const char *method;

                method = va_arg(ap, const char *);
                if (!method)
                        break;

                callback = va_arg(ap, VarlinkMethod);

                r = varlink_server_bind_method(s, method, callback);
                if (r < 0)
                        break;
        }
        va_end(ap);

        return r;
}

int varlink_server_bind_connect(VarlinkServer *s, VarlinkConnect callback) {
        assert_return(s, -EINVAL);

        if (callback && s->connect_callback && callback != s->connect_callback)
                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        s->connect_callback = callback;
        return 0;
}

int varlink_server_bind_disconnect(VarlinkServer *s, VarlinkDisconnect callback) {
        assert_return(s, -EINVAL);

        if (callback && s->disconnect_callback && callback != s->disconnect_callback)
                return log_debug_errno(SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        s->disconnect_callback = callback;
        return 0;
}

unsigned varlink_server_connections_max(VarlinkServer *s) {
        int dts;

        /* If a server is specified, return the setting for that server, otherwise the default value */
        if (s)
                return s->connections_max;

        dts = getdtablesize();
        assert_se(dts > 0);

        /* Make sure we never use up more than ¾th of RLIMIT_NOFILE for IPC */
        if (VARLINK_DEFAULT_CONNECTIONS_MAX > (unsigned) dts / 4 * 3)
                return dts / 4 * 3;

        return VARLINK_DEFAULT_CONNECTIONS_MAX;
}

unsigned varlink_server_connections_per_uid_max(VarlinkServer *s) {
        unsigned m;

        if (s)
                return s->connections_per_uid_max;

        /* Make sure to never use up more than ¾th of available connections for a single user */
        m = varlink_server_connections_max(NULL);
        if (VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX > m)
                return m / 4 * 3;

        return VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX;
}

int varlink_server_set_connections_per_uid_max(VarlinkServer *s, unsigned m) {
        assert_return(s, -EINVAL);
        assert_return(m > 0, -EINVAL);

        s->connections_per_uid_max = m;
        return 0;
}

int varlink_server_set_connections_max(VarlinkServer *s, unsigned m) {
        assert_return(s, -EINVAL);
        assert_return(m > 0, -EINVAL);

        s->connections_max = m;
        return 0;
}

unsigned varlink_server_current_connections(VarlinkServer *s) {
        assert_return(s, UINT_MAX);

        return s->n_connections;
}

int varlink_server_set_description(VarlinkServer *s, const char *description) {
        assert_return(s, -EINVAL);

        return free_and_strdup(&s->description, description);
}
