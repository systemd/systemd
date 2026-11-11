/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-stream.h"
#include "json-util.h"
#include "list.h"
#include "log.h"
#include "memory-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"

#define JSON_STREAM_BUFFER_MAX_DEFAULT (16U * 1024U * 1024U)
#define JSON_STREAM_READ_SIZE_DEFAULT  (64U * 1024U)
#define JSON_STREAM_QUEUE_MAX_DEFAULT  (64U * 1024U)
#define JSON_STREAM_FDS_MAX            (16U * 1024U)

struct JsonStreamQueueItem {
        LIST_FIELDS(JsonStreamQueueItem, queue);
        sd_json_variant *data;
        size_t n_fds;
        int fds[];
};

/* Returns the size of the framing delimiter in bytes: strlen(delimiter) for multi-char
 * delimiters (e.g. "\r\n"), or 1 for the default NUL-byte delimiter (delimiter == NULL). */
static size_t json_stream_delimiter_size(const JsonStream *s) {
        return strlen_ptr(s->delimiter) ?: 1;
}

static usec_t json_stream_now(const JsonStream *s) {
        usec_t t;

        if (s->event && sd_event_now(s->event, CLOCK_MONOTONIC, &t) >= 0)
                return t;

        return now(CLOCK_MONOTONIC);
}

static JsonStreamQueueItem* json_stream_queue_item_free(JsonStreamQueueItem *q) {
        if (!q)
                return NULL;

        sd_json_variant_unref(q->data);
        close_many(q->fds, q->n_fds);

        return mfree(q);
}

static JsonStreamQueueItem* json_stream_queue_item_new(sd_json_variant *m, const int fds[], size_t n_fds) {
        JsonStreamQueueItem *q;

        assert(m);
        assert(fds || n_fds == 0);

        size_t sz = sizeof(int);
        if (!MUL_SAFE(&sz, sz, n_fds) ||
            !INC_SAFE(&sz, offsetof(JsonStreamQueueItem, fds)))
                return NULL;

        q = malloc(sz);
        if (!q)
                return NULL;

        *q = (JsonStreamQueueItem) {
                .data = sd_json_variant_ref(m),
                .n_fds = n_fds,
        };

        memcpy_safe(q->fds, fds, n_fds * sizeof(int));

        return TAKE_PTR(q);
}

int json_stream_init(JsonStream *s, const JsonStreamParams *params) {
        assert(s);
        assert(params);
        assert(params->phase);
        assert(params->dispatch);

        char *delimiter = NULL;
        if (params->delimiter) {
                delimiter = strdup(params->delimiter);
                if (!delimiter)
                        return -ENOMEM;
        }

        *s = (JsonStream) {
                .delimiter = delimiter,
                .buffer_max = params->buffer_max > 0 ? params->buffer_max : JSON_STREAM_BUFFER_MAX_DEFAULT,
                .read_chunk = params->read_chunk > 0 ? params->read_chunk : JSON_STREAM_READ_SIZE_DEFAULT,
                .queue_max = params->queue_max > 0 ? params->queue_max : JSON_STREAM_QUEUE_MAX_DEFAULT,
                .phase_cb = params->phase,
                .dispatch_cb = params->dispatch,
                .userdata = params->userdata,
                .input_fd = -EBADF,
                .output_fd = -EBADF,
                .timeout = USEC_INFINITY,
                .last_activity = USEC_INFINITY,
                .ucred = UCRED_INVALID,
                .peer_pidfd = -EBADF,
                .af = -1,
        };

        return 0;
}

static void json_stream_clear(JsonStream *s) {
        if (!s)
                return;

        json_stream_detach_event(s);

        s->delimiter = mfree(s->delimiter);
        s->description = mfree(s->description);

        if (s->input_fd != s->output_fd) {
                s->input_fd = safe_close(s->input_fd);
                s->output_fd = safe_close(s->output_fd);
        } else
                s->output_fd = s->input_fd = safe_close(s->input_fd);
        s->input_socket_type = 0;

        s->peer_pidfd = safe_close(s->peer_pidfd);
        s->ucred_acquired = s->ucred_overridden = false;
        s->af = -1;

        close_many(s->input_fds, s->n_input_fds);
        s->input_fds = mfree(s->input_fds);
        s->n_input_fds = 0;

        s->input_buffer = FLAGS_SET(s->flags, JSON_STREAM_INPUT_SENSITIVE) ? erase_and_free(s->input_buffer) : mfree(s->input_buffer);
        s->input_buffer_index = s->input_buffer_size = s->input_buffer_unscanned = 0;

        s->output_buffer = FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE) ? erase_and_free(s->output_buffer) : mfree(s->output_buffer);
        s->output_buffer_index = s->output_buffer_size = 0;
        s->flags &= ~JSON_STREAM_OUTPUT_BUFFER_SENSITIVE;

        s->input_control_buffer = mfree(s->input_control_buffer);
        s->input_control_buffer_size = 0;

        close_many(s->output_fds, s->n_output_fds);
        s->output_fds = mfree(s->output_fds);
        s->n_output_fds = 0;

        LIST_CLEAR(queue, s->output_queue, json_stream_queue_item_free);
        s->output_queue_tail = NULL;
        s->n_output_queue = 0;
}

void json_stream_done(JsonStream *s) {
        if (!s)
                return;

        json_stream_clear(s);
}

int json_stream_set_description(JsonStream *s, const char *description) {
        assert(s);
        return free_and_strdup(&s->description, description);
}

const char* json_stream_get_description(const JsonStream *s) {
        assert(s);
        return s->description;
}

int json_stream_connect_address(JsonStream *s, const char *address) {
        union sockaddr_union sockaddr;
        int r;

        assert(s);
        assert(address);

        _cleanup_close_ int sock_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (sock_fd < 0)
                return json_stream_log_errno(s, errno, "Failed to create AF_UNIX socket: %m");

        sock_fd = fd_move_above_stdio(sock_fd);

        r = sockaddr_un_set_path(&sockaddr.un, address);
        if (r < 0) {
                if (r != -ENAMETOOLONG)
                        return json_stream_log_errno(s, r, "Failed to set socket address '%s': %m", address);

                /* Path too long to fit into sockaddr_un, connect via O_PATH instead. */
                r = connect_unix_path(sock_fd, AT_FDCWD, address);
        } else
                r = RET_NERRNO(connect(sock_fd, &sockaddr.sa, r));
        if (r < 0) {
                if (!IN_SET(r, -EAGAIN, -EINPROGRESS))
                        return json_stream_log_errno(s, r, "Failed to connect to %s: %m", address);

                /* The connect() is being processed in the background. As long as that's the
                 * case the socket is in a special state: we can poll it for POLLOUT, but
                 * write()s before POLLOUT will fail with ENOTCONN (rather than EAGAIN). Since
                 * ENOTCONN can mean two different things (not yet connected vs. already
                 * disconnected), we track this as a separate flag. */
                s->flags |= JSON_STREAM_CONNECTING;
        }

        r = json_stream_attach_fds(s, sock_fd, sock_fd);
        if (r < 0)
                return r;

        TAKE_FD(sock_fd);
        return 0;
}

int json_stream_attach_fds(JsonStream *s, int input_fd, int output_fd) {
        struct stat st;
        int input_socket_type = 0, r;

        assert(s);
        assert(input_fd >= 0);
        assert(input_fd != s->input_fd);
        assert(input_fd != s->output_fd);
        assert(output_fd >= 0);
        assert(output_fd != s->input_fd);
        assert(output_fd != s->output_fd);

        /* NB: input_fd and output_fd are donated to the JsonStream instance on success. */

        JsonStreamFlags flags = s->flags & ~(JSON_STREAM_PREFER_READ|JSON_STREAM_PREFER_WRITE);

        /* Detect non-socket fds up front so the read/write paths use read()/write() for
         * non-socket fds and send()/recv() for sockets (mostly for MSG_NOSIGNAL). */
        if (input_fd >= 0) {
                if (fstat(input_fd, &st) < 0)
                        return -errno;
                if (!S_ISSOCK(st.st_mode))
                        flags |= JSON_STREAM_PREFER_READ;
                else {
                        r = getsockopt_int(input_fd, SOL_SOCKET, SO_TYPE, &input_socket_type);
                        if (r < 0)
                                return r;
                }
        }

        if (output_fd >= 0 && output_fd != input_fd) {
                if (fstat(output_fd, &st) < 0)
                        return -errno;
                if (!S_ISSOCK(st.st_mode))
                        flags |= JSON_STREAM_PREFER_WRITE;
        } else if (FLAGS_SET(flags, JSON_STREAM_PREFER_READ))
                flags |= JSON_STREAM_PREFER_WRITE;

        if (s->input_fd != s->output_fd)
                safe_close(s->output_fd);
        safe_close(s->input_fd);

        s->input_fd = input_fd;
        s->output_fd = output_fd;
        s->input_socket_type = input_socket_type;
        s->flags = flags;
        return 0;
}

int json_stream_connect_fd_pair(JsonStream *s, int input_fd, int output_fd) {
        int r;

        assert(s);
        assert(input_fd >= 0);
        assert(output_fd >= 0);

        /* NB: input_fd and output_fd are donated to the JsonStream instance on success.
         * The fds may be changed to non-blocking mode even on failure. */

        r = fd_nonblock(input_fd, /* nonblock= */ true);
        if (r < 0)
                return json_stream_log_errno(s, r, "Failed to make input fd %d nonblocking: %m", input_fd);

        if (input_fd != output_fd) {
                r = fd_nonblock(output_fd, /* nonblock= */ true);
                if (r < 0)
                        return json_stream_log_errno(s, r, "Failed to make output fd %d nonblocking: %m", output_fd);
        }

        return json_stream_attach_fds(s, input_fd, output_fd);
}

bool json_stream_flags_set(const JsonStream *s, JsonStreamFlags flags) {
        assert(s);
        assert((flags & ~(JSON_STREAM_BOUNDED_READS|JSON_STREAM_INPUT_SENSITIVE|JSON_STREAM_ALLOW_FD_PASSING_INPUT|JSON_STREAM_ALLOW_FD_PASSING_OUTPUT)) == 0);

        return FLAGS_SET(s->flags, flags);
}

/* Multiple flags may be passed — all are set or cleared together. */
void json_stream_set_flags(JsonStream *s, JsonStreamFlags flags, bool b) {
        assert(s);
        assert((flags & ~(JSON_STREAM_BOUNDED_READS|JSON_STREAM_INPUT_SENSITIVE)) == 0);

        SET_FLAG(s->flags, flags, b);
}

bool json_stream_has_buffered_input(const JsonStream *s) {
        assert(s);
        return s->input_buffer_size > 0;
}

/* Query the consumer's current phase. The callback is mandatory (asserted at construction
 * time), so we can call it unconditionally. */
static JsonStreamPhase json_stream_current_phase(const JsonStream *s) {
        assert(s);
        return s->phase_cb(s->userdata);
}

/* Both READING and AWAITING_REPLY mean "we want POLLIN and would lose if the read side
 * died" — they only differ in whether the idle timeout is in force. */
static bool phase_is_reading(JsonStreamPhase p) {
        return IN_SET(p, JSON_STREAM_PHASE_READING, JSON_STREAM_PHASE_AWAITING_REPLY);
}

bool json_stream_should_disconnect(const JsonStream *s) {
        assert(s);

        /* Carefully decide when the consumer should initiate a teardown. We err on the side
         * of staying around so half-open connections can flush remaining data and reads can
         * surface buffered messages before we tear everything down. */

        /* Wait until any in-flight async connect() completes — there's nothing reasonable
         * to do until we know whether the socket is connected or not. */
        if (FLAGS_SET(s->flags, JSON_STREAM_CONNECTING))
                return false;

        /* Still bytes to write and we can write? Stay around so the flush can complete. */
        if (s->output_buffer_size > 0 && !FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED))
                return false;

        /* Both sides gone already? Then there's no point in lingering. */
        if (FLAGS_SET(s->flags, JSON_STREAM_READ_DISCONNECTED|JSON_STREAM_WRITE_DISCONNECTED))
                return true;

        JsonStreamPhase phase = json_stream_current_phase(s);

        /* Caller is waiting for input but the read side is shut down — we'll never see
         * another message. */
        if (phase_is_reading(phase) && FLAGS_SET(s->flags, JSON_STREAM_READ_DISCONNECTED))
                return true;

        /* Idle client whose write side has died, or we saw POLLHUP. We explicitly check for
         * POLLHUP because we likely won't notice the write side being down via send() if we
         * never wrote anything in the first place. */
        if (phase == JSON_STREAM_PHASE_IDLE_CLIENT &&
            (s->flags & (JSON_STREAM_WRITE_DISCONNECTED|JSON_STREAM_GOT_POLLHUP)))
                return true;

        /* Caller has more output to send but the peer hung up, and we're either out of
         * bytes or already saw a write error. Nothing left to do. */
        if (phase == JSON_STREAM_PHASE_PENDING_OUTPUT &&
            (FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED) || s->output_buffer_size == 0) &&
            FLAGS_SET(s->flags, JSON_STREAM_GOT_POLLHUP))
                return true;

        return false;
}

int json_stream_get_events(const JsonStream *s) {
        int ret = 0;

        assert(s);

        /* While an asynchronous connect() is still in flight we only ask for POLLOUT, which
         * tells us once the connection is fully established. We must not read or write before
         * that. */
        if (FLAGS_SET(s->flags, JSON_STREAM_CONNECTING))
                return POLLOUT;

        if (phase_is_reading(json_stream_current_phase(s)) &&
            !FLAGS_SET(s->flags, JSON_STREAM_READ_DISCONNECTED) &&
            s->input_buffer_unscanned == 0)
                ret |= POLLIN;

        if (!FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED) && (s->output_queue || s->output_buffer_size > 0))
                ret |= POLLOUT;

        return ret;
}

static void json_stream_handle_revents(JsonStream *s, int revents) {
        assert(s);

        if (FLAGS_SET(s->flags, JSON_STREAM_CONNECTING)) {
                /* If we have seen POLLOUT or POLLHUP on a socket we are asynchronously waiting a
                 * connect() to complete on, we know we are ready. We don't read the connection
                 * error here though — we'll get it on the next read() or write(). */
                if ((revents & (POLLOUT|POLLHUP)) == 0)
                        return;

                json_stream_log(s, "Asynchronous connection completed.");
                s->flags &= ~JSON_STREAM_CONNECTING;
                return;
        }

        /* Note that we don't care much about POLLIN/POLLOUT here, we'll just try reading and
         * writing what we can. However, we do care about POLLHUP to detect connection
         * termination even if we momentarily don't want to read nor write anything. */
        if (FLAGS_SET(revents, POLLHUP)) {
                json_stream_log(s, "Got POLLHUP from socket.");
                s->flags |= JSON_STREAM_GOT_POLLHUP;
        }
}

int json_stream_wait(JsonStream *s, usec_t timeout) {
        int events, r;

        assert(s);

        events = json_stream_get_events(s);
        if (events < 0)
                return events;

        /* MIN the caller's timeout with our own deadline (if any) so that we wake up to
         * fire the idle timeout. */
        usec_t deadline = json_stream_get_timeout(s);
        if (deadline != USEC_INFINITY)
                timeout = MIN(timeout, usec_sub_unsigned(deadline, now(CLOCK_MONOTONIC)));

        struct pollfd pollfd[2];
        size_t n_poll_fd = 0;

        if (s->input_fd == s->output_fd) {
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = s->input_fd,
                        .events = events,
                };
        } else {
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = s->input_fd,
                        .events = events & POLLIN,
                };
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = s->output_fd,
                        .events = events & POLLOUT,
                };
        }

        r = ppoll_usec(pollfd, n_poll_fd, timeout);
        if (ERRNO_IS_NEG_TRANSIENT(r))
                /* Treat EINTR as not a timeout, but also nothing happened, and the caller gets
                 * a chance to call back into us. */
                return 1;
        if (r <= 0)
                return r;

        int revents = 0;
        FOREACH_ARRAY(p, pollfd, n_poll_fd)
                revents |= p->revents;

        json_stream_handle_revents(s, revents);
        return 1;
}

/* ===== Timeout management ===== */

static usec_t json_stream_get_deadline(const JsonStream *s) {
        assert(s);

        return usec_add(s->last_activity, s->timeout);
}

usec_t json_stream_get_timeout(const JsonStream *s) {
        assert(s);

        /* The deadline is in force only when the consumer is in PHASE_AWAITING_REPLY. In
         * other phases (idle server, between operations) we ignore the cached deadline even
         * if it's still set from a previous operation. */
        if (json_stream_current_phase(s) != JSON_STREAM_PHASE_AWAITING_REPLY)
                return USEC_INFINITY;

        return json_stream_get_deadline(s);
}

static void json_stream_rearm_time_source(JsonStream *s) {
        int r;

        assert(s);

        if (!s->time_event_source)
                return;

        usec_t deadline = json_stream_get_timeout(s);
        if (deadline == USEC_INFINITY) {
                (void) sd_event_source_set_enabled(s->time_event_source, SD_EVENT_OFF);
                return;
        }

        r = sd_event_source_set_time(s->time_event_source, deadline);
        if (r < 0) {
                json_stream_log_errno(s, r, "Failed to set time source deadline: %m");
                return;
        }

        (void) sd_event_source_set_enabled(s->time_event_source, SD_EVENT_ON);
}

void json_stream_set_timeout(JsonStream *s, usec_t timeout) {
        assert(s);

        s->timeout = timeout;

        /* If the configured timeout changes mid-flight, rearm the time source so the new
         * deadline takes effect immediately rather than waiting for the next mark_activity
         * or successful write. */
        json_stream_rearm_time_source(s);
}

void json_stream_mark_activity(JsonStream *s) {
        assert(s);

        s->last_activity = json_stream_now(s);
        json_stream_rearm_time_source(s);
}

static int json_stream_acquire_peer_ucred(JsonStream *s, struct ucred *ret) {
        int r;

        assert(s);
        assert(ret);

        if (!s->ucred_acquired) {
                /* Peer credentials only make sense for a bidirectional socket. */
                if (s->input_fd != s->output_fd)
                        return -EBADF;

                r = getpeercred(s->input_fd, &s->ucred);
                if (r < 0)
                        return r;

                s->ucred_acquired = true;
        }

        *ret = s->ucred;
        return 0;
}

int json_stream_acquire_peer_uid(JsonStream *s, uid_t *ret) {
        struct ucred ucred;
        int r;

        assert(s);
        assert(ret);

        r = json_stream_acquire_peer_ucred(s, &ucred);
        if (r < 0)
                return json_stream_log_errno(s, r, "Failed to acquire credentials: %m");

        if (!uid_is_valid(ucred.uid))
                return json_stream_log_errno(s, SYNTHETIC_ERRNO(ENODATA), "Peer UID is invalid.");

        *ret = ucred.uid;
        return 0;
}

int json_stream_acquire_peer_gid(JsonStream *s, gid_t *ret) {
        struct ucred ucred;
        int r;

        assert(s);
        assert(ret);

        r = json_stream_acquire_peer_ucred(s, &ucred);
        if (r < 0)
                return json_stream_log_errno(s, r, "Failed to acquire credentials: %m");

        if (!gid_is_valid(ucred.gid))
                return json_stream_log_errno(s, SYNTHETIC_ERRNO(ENODATA), "Peer GID is invalid.");

        *ret = ucred.gid;
        return 0;
}

int json_stream_acquire_peer_pid(JsonStream *s, pid_t *ret) {
        struct ucred ucred;
        int r;

        assert(s);
        assert(ret);

        r = json_stream_acquire_peer_ucred(s, &ucred);
        if (r < 0)
                return json_stream_log_errno(s, r, "Failed to acquire credentials: %m");

        if (!pid_is_valid(ucred.pid))
                return json_stream_log_errno(s, SYNTHETIC_ERRNO(ENODATA), "Peer PID is invalid.");

        *ret = ucred.pid;
        return 0;
}

int json_stream_get_peer_ucred(const JsonStream *s, struct ucred *ret) {
        assert(s);
        assert(ret);

        if (!s->ucred_acquired)
                return -ENODATA;

        *ret = s->ucred;
        return 0;
}

void json_stream_set_peer_ucred(JsonStream *s, const struct ucred *ucred, bool overridden) {
        assert(s);
        assert(ucred);

        s->ucred = *ucred;
        s->ucred_acquired = true;
        s->ucred_overridden = overridden;
}

int json_stream_acquire_peer_pidfd(JsonStream *s) {
        assert(s);

        if (s->peer_pidfd >= 0)
                return s->peer_pidfd;

        if (s->input_fd != s->output_fd)
                return json_stream_log_errno(s, SYNTHETIC_ERRNO(EBADF), "Failed to acquire pidfd of peer: separate input/output fds");

        s->peer_pidfd = getpeerpidfd(s->input_fd);
        if (s->peer_pidfd < 0)
                return json_stream_log_errno(s, s->peer_pidfd, "Failed to acquire pidfd of peer: %m");

        return s->peer_pidfd;
}

static int json_stream_verify_unix_socket(JsonStream *s) {
        assert(s);

        /* Returns:
         *    • 0 if this is an AF_UNIX socket
         *    • -ENOTSOCK if this is not a socket at all
         *    • -ENOMEDIUM if this is a socket, but not an AF_UNIX socket
         *
         * The result is cached after the first call. af < 0 = unchecked, af == AF_UNSPEC =
         * checked but not a socket, otherwise af is the resolved address family. */

        if (s->af < 0) {
                /* If we have distinct input + output fds, we don't consider ourselves to be
                 * connected via a regular AF_UNIX socket. */
                if (s->input_fd != s->output_fd) {
                        s->af = AF_UNSPEC;
                        return -ENOTSOCK;
                }

                struct stat st;

                if (fstat(s->input_fd, &st) < 0)
                        return -errno;
                if (!S_ISSOCK(st.st_mode)) {
                        s->af = AF_UNSPEC;
                        return -ENOTSOCK;
                }

                s->af = socket_get_family(s->input_fd);
                if (s->af < 0)
                        return s->af;
        }

        if (s->af == AF_UNIX)
                return 0;
        if (s->af == AF_UNSPEC)
                return -ENOTSOCK;

        return -ENOMEDIUM;
}

int json_stream_set_allow_fd_passing_input(JsonStream *s, bool enabled, bool with_sockopt) {
        int r;

        assert(s);

        if (FLAGS_SET(s->flags, JSON_STREAM_ALLOW_FD_PASSING_INPUT) == enabled)
                return 0;

        r = json_stream_verify_unix_socket(s);
        if (r < 0) {
                /* If the caller is disabling, accept the verify failure silently — we just
                 * leave the flag as it was (or set it to false if currently true). */
                if (!enabled) {
                        s->flags &= ~JSON_STREAM_ALLOW_FD_PASSING_INPUT;
                        return 0;
                }
                return r;
        }

        if (with_sockopt) {
                r = setsockopt_int(s->input_fd, SOL_SOCKET, SO_PASSRIGHTS, enabled);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        json_stream_log_errno(s, r, "Failed to set SO_PASSRIGHTS socket option: %m");
        }

        SET_FLAG(s->flags, JSON_STREAM_ALLOW_FD_PASSING_INPUT, enabled);
        return 1;
}

int json_stream_set_allow_fd_passing_output(JsonStream *s, bool enabled) {
        int r;

        assert(s);

        if (FLAGS_SET(s->flags, JSON_STREAM_ALLOW_FD_PASSING_OUTPUT) == enabled)
                return 0;

        r = json_stream_verify_unix_socket(s);
        if (r < 0)
                return r;

        SET_FLAG(s->flags, JSON_STREAM_ALLOW_FD_PASSING_OUTPUT, enabled);
        return 1;
}

/* ===== sd-event integration ===== */

static int json_stream_io_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        JsonStream *s = ASSERT_PTR(userdata);
        int r;

        json_stream_handle_revents(s, revents);

        r = s->dispatch_cb(s->userdata);
        if (r < 0)
                json_stream_log_errno(s, r, "Dispatch callback failed, ignoring: %m");

        return 1;
}

static int json_stream_time_callback(sd_event_source *source, uint64_t usec, void *userdata) {
        JsonStream *s = ASSERT_PTR(userdata);
        int r;

        /* Disable the source: it must not fire again until activity is marked. The consumer
         * notices the timeout by comparing now() to json_stream_get_timeout() in its dispatch
         * callback. */
        (void) sd_event_source_set_enabled(s->time_event_source, SD_EVENT_OFF);

        r = s->dispatch_cb(s->userdata);
        if (r < 0)
                json_stream_log_errno(s, r, "Dispatch callback failed, ignoring: %m");

        return 1;
}

static int json_stream_prepare_callback(sd_event_source *source, void *userdata) {
        JsonStream *s = ASSERT_PTR(userdata);
        int r, e;

        e = json_stream_get_events(s);
        if (e < 0)
                return e;

        if (s->input_event_source == s->output_event_source)
                /* Same fd for input + output */
                r = sd_event_source_set_io_events(s->input_event_source, e);
        else {
                r = sd_event_source_set_io_events(s->input_event_source, e & POLLIN);
                if (r >= 0)
                        r = sd_event_source_set_io_events(s->output_event_source, e & POLLOUT);
        }
        if (r < 0)
                return json_stream_log_errno(s, r, "Failed to set io events: %m");

        /* Rearm the timeout on every prepare cycle so that phase transitions (e.g. entering
         * AWAITING_REPLY) are picked up without requiring the consumer to explicitly call
         * mark_activity at every state change. */
        json_stream_rearm_time_source(s);

        return 1;
}

void json_stream_detach_event(JsonStream *s) {
        if (!s)
                return;

        s->input_event_source = sd_event_source_disable_unref(s->input_event_source);
        s->output_event_source = sd_event_source_disable_unref(s->output_event_source);
        s->time_event_source = sd_event_source_disable_unref(s->time_event_source);
        s->event = sd_event_unref(s->event);
}

sd_event* json_stream_get_event(const JsonStream *s) {
        assert(s);
        return s->event;
}

int json_stream_attach_event(JsonStream *s, sd_event *event, int64_t priority) {
        int r;

        assert(s);
        assert(!s->event);
        assert(s->input_fd >= 0);
        assert(s->output_fd >= 0);

        if (event)
                s->event = sd_event_ref(event);
        else {
                r = sd_event_default(&s->event);
                if (r < 0)
                        return json_stream_log_errno(s, r, "Failed to acquire default event loop: %m");
        }

        r = sd_event_add_io(s->event, &s->input_event_source, s->input_fd, /* events= */ 0, json_stream_io_callback, s);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(s->input_event_source, json_stream_prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(s->input_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(s->input_event_source, "json-stream-input");

        if (s->input_fd == s->output_fd)
                s->output_event_source = sd_event_source_ref(s->input_event_source);
        else {
                r = sd_event_add_io(s->event, &s->output_event_source, s->output_fd, /* events= */ 0, json_stream_io_callback, s);
                if (r < 0)
                        goto fail;

                r = sd_event_source_set_priority(s->output_event_source, priority);
                if (r < 0)
                        goto fail;

                (void) sd_event_source_set_description(s->output_event_source, "json-stream-output");
        }

        r = sd_event_add_time(s->event, &s->time_event_source, CLOCK_MONOTONIC, /* usec= */ 0, /* accuracy= */ 0,
                              json_stream_time_callback, s);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(s->time_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(s->time_event_source, "json-stream-time");

        /* Initially disabled — only enabled by mark_activity once a timeout is configured. */
        (void) sd_event_source_set_enabled(s->time_event_source, SD_EVENT_OFF);
        json_stream_rearm_time_source(s);

        return 0;

fail:
        json_stream_log_errno(s, r, "Failed to attach event source: %m");
        json_stream_detach_event(s);
        return r;
}

int json_stream_has_buffered_output(const JsonStream *s) {
        assert(s);

        if (s->output_buffer_size == 0 && !s->output_queue)
                return false;

        if (FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED))
                return -ECONNRESET;

        return true;
}

int json_stream_flush(JsonStream *s) {
        int ret = 0, r;

        assert(s);

        for (;;) {
                r = json_stream_has_buffered_output(s);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = json_stream_write(s);
                if (r < 0)
                        return r;
                if (r > 0) {
                        ret = 1;
                        continue;
                }

                r = json_stream_wait(s, USEC_INFINITY);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return json_stream_log_errno(s, r, "Poll failed on fd: %m");
                assert(r > 0);
        }

        return ret;
}

int json_stream_peek_input_fd(const JsonStream *s, size_t i) {
        assert(s);

        if (i >= s->n_input_fds)
                return -ENXIO;

        return s->input_fds[i];
}

int json_stream_take_input_fd(JsonStream *s, size_t i) {
        assert(s);

        if (i >= s->n_input_fds)
                return -ENXIO;

        return TAKE_FD(s->input_fds[i]);
}

size_t json_stream_get_n_input_fds(const JsonStream *s) {
        assert(s);
        return s->n_input_fds;
}

void json_stream_close_input_fds(JsonStream *s) {
        assert(s);

        close_many(s->input_fds, s->n_input_fds);
        s->input_fds = mfree(s->input_fds);
        s->n_input_fds = 0;
}

/* ===== Output formatting ===== */

static int json_stream_format_json(JsonStream *s, sd_json_variant *m) {
        _cleanup_(erase_and_freep) char *text = NULL;
        ssize_t sz, r;

        assert(s);
        assert(m);

        sz = sd_json_variant_format(m, /* flags= */ 0, &text);
        if (sz < 0)
                return sz;
        assert(text[sz] == '\0');

        size_t dsz = json_stream_delimiter_size(s);

        /* Append the framing delimiter after the formatted JSON. For varlink (delimiter ==
         * NULL) this keeps the trailing NUL already placed by sd_json_variant_format(); for
         * multi-char delimiters (e.g. "\r\n") we grow the buffer and copy them in. */
        if (s->delimiter) {
                if (!GREEDY_REALLOC(text, sz + dsz))
                        return -ENOMEM;
                memcpy(text + sz, s->delimiter, dsz);
        }

        if (s->output_buffer_size + sz + dsz > s->buffer_max)
                return -ENOBUFS;

        if (DEBUG_LOGGING) {
                _cleanup_(erase_and_freep) char *censored_text = NULL;

                /* Suppress sensitive fields in the debug output */
                r = sd_json_variant_format(m, SD_JSON_FORMAT_CENSOR_SENSITIVE, &censored_text);
                if (r >= 0)
                        json_stream_log(s, "Sending message: %s", censored_text);
        }

        if (s->output_buffer_size == 0) {
                if (FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE)) {
                        s->output_buffer = erase_and_free(s->output_buffer);
                        s->flags &= ~JSON_STREAM_OUTPUT_BUFFER_SENSITIVE;
                }

                free_and_replace(s->output_buffer, text);

                s->output_buffer_size = sz + dsz;
                s->output_buffer_index = 0;

        } else if (!FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE) && s->output_buffer_index == 0) {
                if (!GREEDY_REALLOC(s->output_buffer, s->output_buffer_size + sz + dsz))
                        return -ENOMEM;

                memcpy(s->output_buffer + s->output_buffer_size, text, sz + dsz);
                s->output_buffer_size += sz + dsz;
        } else {
                const size_t new_size = s->output_buffer_size + sz + dsz;

                char *n = new(char, new_size);
                if (!n)
                        return -ENOMEM;

                memcpy(mempcpy(n, s->output_buffer + s->output_buffer_index, s->output_buffer_size), text, sz + dsz);

                if (FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE))
                        s->output_buffer = erase_and_free(s->output_buffer);
                else
                        free(s->output_buffer);
                s->output_buffer = n;
                s->output_buffer_size = new_size;
                s->output_buffer_index = 0;
        }

        if (sd_json_variant_is_sensitive_recursive(m))
                s->flags |= JSON_STREAM_OUTPUT_BUFFER_SENSITIVE;
        else
                text = mfree(text); /* Skip the erase_and_free() destructor declared above */

        return 0;
}

static int json_stream_format_queue(JsonStream *s) {
        int r;

        assert(s);

        /* Drain entries out of the output queue and format them into the output buffer.
         * Stop if there are unwritten output_fds or if the next item carries fds but
         * the output buffer is non-empty, since adding more would corrupt the fd boundary. */

        while (s->output_queue) {
                assert(s->n_output_queue > 0);

                if (s->n_output_fds > 0)
                        return 0;

                JsonStreamQueueItem *q = s->output_queue;

                /* If the next item carries fds but the output buffer still holds bytes from
                 * a prior fast-path enqueue or a partial write, we must not concatenate its
                 * JSON into that same buffer: the subsequent sendmsg() in json_stream_write()
                 * would attach the fds to the combined bytes and break the message-to-fd boundary.
                 * Stop here and let json_stream_write() drain the buffer first; the next write()
                 * call will pull this item into a clean buffer.
                 *
                 * On AF_UNIX SOCK_STREAM, separate sendmsg() calls alone are not sufficient:
                 * recvmsg() may combine preceding data with the next SCM_RIGHTS-bearing send.
                 * The receive side must also stop at message boundaries to keep the association. */
                if (q->n_fds > 0 && s->output_buffer_size > 0)
                        return 0;

                _cleanup_free_ int *array = NULL;
                if (q->n_fds > 0) {
                        array = newdup(int, q->fds, q->n_fds);
                        if (!array)
                                return -ENOMEM;
                }

                r = json_stream_format_json(s, q->data);
                if (r < 0)
                        return r;

                free_and_replace(s->output_fds, array);
                s->n_output_fds = q->n_fds;
                q->n_fds = 0;

                LIST_REMOVE(queue, s->output_queue, q);
                if (!s->output_queue)
                        s->output_queue_tail = NULL;
                s->n_output_queue--;

                json_stream_queue_item_free(q);
        }

        return 0;
}

int json_stream_enqueue_full(JsonStream *s, sd_json_variant *m, const int fds[], size_t n_fds) {
        assert(s);
        assert(m);
        assert(fds || n_fds == 0);

        /* Fast path: no fds and no items currently queued — append directly into the
         * output buffer to avoid the queue allocation. */
        if (n_fds == 0 && !s->output_queue)
                return json_stream_format_json(s, m);

        if (s->n_output_queue >= s->queue_max)
                return -ENOBUFS;

        JsonStreamQueueItem *q = json_stream_queue_item_new(m, fds, n_fds);
        if (!q)
                return -ENOMEM;

        LIST_INSERT_AFTER(queue, s->output_queue, s->output_queue_tail, q);
        s->output_queue_tail = q;
        s->n_output_queue++;
        return 0;
}

/* ===== Write side ===== */

int json_stream_write(JsonStream *s) {
        ssize_t n;
        int r;

        assert(s);

        if (FLAGS_SET(s->flags, JSON_STREAM_CONNECTING))
                return 0;
        if (FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED))
                return 0;

        /* Drain the deferred queue into the output buffer if possible */
        r = json_stream_format_queue(s);
        if (r < 0)
                return r;

        if (s->output_buffer_size == 0)
                return 0;

        assert(s->output_fd >= 0);

        if (s->n_output_fds > 0) {
                struct iovec iov = {
                        .iov_base = s->output_buffer + s->output_buffer_index,
                        .iov_len = s->output_buffer_size,
                };
                struct msghdr mh = {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_controllen = CMSG_SPACE(sizeof(int) * s->n_output_fds),
                };

                mh.msg_control = alloca0(mh.msg_controllen);

                struct cmsghdr *control = CMSG_FIRSTHDR(&mh);
                control->cmsg_len = CMSG_LEN(sizeof(int) * s->n_output_fds);
                control->cmsg_level = SOL_SOCKET;
                control->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(control), s->output_fds, sizeof(int) * s->n_output_fds);

                n = sendmsg(s->output_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        } else if (FLAGS_SET(s->flags, JSON_STREAM_PREFER_WRITE))
                n = write(s->output_fd, s->output_buffer + s->output_buffer_index, s->output_buffer_size);
        else
                n = send(s->output_fd, s->output_buffer + s->output_buffer_index, s->output_buffer_size, MSG_DONTWAIT|MSG_NOSIGNAL);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        s->flags |= JSON_STREAM_WRITE_DISCONNECTED;
                        return 1;
                }

                return -errno;
        }

        if (FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE))
                explicit_bzero_safe(s->output_buffer + s->output_buffer_index, n);

        s->output_buffer_size -= n;

        if (s->output_buffer_size == 0) {
                s->output_buffer_index = 0;
                s->flags &= ~JSON_STREAM_OUTPUT_BUFFER_SENSITIVE;
        } else
                s->output_buffer_index += n;

        close_many(s->output_fds, s->n_output_fds);
        s->n_output_fds = 0;

        /* Refresh activity timestamp on real progress (and rearm the time source if attached
         * to an event loop). */
        s->last_activity = json_stream_now(s);
        json_stream_rearm_time_source(s);

        return 1;
}

/* ===== Read side ===== */

/* Peek at the socket data to find the delimiter and return a read size that won't consume past it.
 * Besides preserving data for protocol handoff, this keeps SCM_RIGHTS from a later message from being
 * received with an earlier message that carries no file descriptors. Falls back to byte-by-byte for
 * non-socket fds where MSG_PEEK is not available. */
static ssize_t json_stream_peek_message_boundary(JsonStream *s, void *p, size_t rs) {
        assert(s);

        if ((s->flags & (JSON_STREAM_BOUNDED_READS|JSON_STREAM_ALLOW_FD_PASSING_INPUT)) == 0)
                return rs;

        /* Packet sockets already preserve the FD boundary. Shortening their reads would truncate data. */
        if (s->input_socket_type != SOCK_STREAM && !FLAGS_SET(s->flags, JSON_STREAM_BOUNDED_READS))
                return rs;

        if (FLAGS_SET(s->flags, JSON_STREAM_PREFER_READ))
                return 1;

        ssize_t peeked = recv(s->input_fd, p, rs, MSG_PEEK|MSG_DONTWAIT);
        if (peeked < 0) {
                /* Let the actual read classify disconnections and update the stream state. */
                if (ERRNO_IS_DISCONNECT(errno))
                        return rs;
                if (!ERRNO_IS_TRANSIENT(errno))
                        return -errno;

                /* Transient error: shouldn't happen but fall back to byte-by-byte */
                return 1;
        }
        /* EOF: the real recv() will also see it; what we return here doesn't matter */
        if (peeked == 0)
                return rs;

        size_t dsz = json_stream_delimiter_size(s);
        /* Include the buffered suffix in case the delimiter straddles the old and new data. */
        size_t rescan = MIN(s->input_buffer_size, dsz - 1);
        void *delim = memmem_safe((char*) p - rescan, rescan + peeked, s->delimiter ?: "\0", dsz);
        if (delim)
                return (char*) delim + dsz - (char*) p;

        return peeked;
}

int json_stream_read(JsonStream *s) {
        struct iovec iov;
        struct msghdr mh;
        ssize_t rs;
        ssize_t n;
        void *p;

        assert(s);

        if (FLAGS_SET(s->flags, JSON_STREAM_CONNECTING))
                return 0;
        if (s->input_buffer_unscanned > 0)
                return 0;
        if (FLAGS_SET(s->flags, JSON_STREAM_READ_DISCONNECTED))
                return 0;

        if (s->input_buffer_size >= s->buffer_max)
                return -ENOBUFS;

        assert(s->input_fd >= 0);

        if (MALLOC_SIZEOF_SAFE(s->input_buffer) <= s->input_buffer_index + s->input_buffer_size) {
                size_t add;

                add = MIN(s->buffer_max - s->input_buffer_size, s->read_chunk);

                if (s->input_buffer_index == 0 &&
                    (!FLAGS_SET(s->flags, JSON_STREAM_INPUT_SENSITIVE) || s->input_buffer_size == 0)) {
                        if (!GREEDY_REALLOC(s->input_buffer, s->input_buffer_size + add))
                                return -ENOMEM;
                } else {
                        char *b;

                        b = new(char, s->input_buffer_size + add);
                        if (!b)
                                return -ENOMEM;

                        memcpy(b, s->input_buffer + s->input_buffer_index, s->input_buffer_size);

                        if (FLAGS_SET(s->flags, JSON_STREAM_INPUT_SENSITIVE))
                                s->input_buffer = erase_and_free(s->input_buffer);
                        else
                                free(s->input_buffer);
                        s->input_buffer = b;
                        s->input_buffer_index = 0;
                }
        }

        p = s->input_buffer + s->input_buffer_index + s->input_buffer_size;

        rs = MALLOC_SIZEOF_SAFE(s->input_buffer) - (s->input_buffer_index + s->input_buffer_size);

        /* Preserve message boundaries when receiving file descriptors or preparing a protocol upgrade. */
        rs = json_stream_peek_message_boundary(s, p, rs);
        if (rs < 0)
                return json_stream_log_errno(s, (int) rs, "Failed to peek message boundary: %m");

        if (FLAGS_SET(s->flags, JSON_STREAM_ALLOW_FD_PASSING_INPUT)) {
                iov = IOVEC_MAKE(p, rs);

                if (!s->input_control_buffer) {
                        s->input_control_buffer_size = CMSG_SPACE(sizeof(int) * JSON_STREAM_FDS_MAX);
                        s->input_control_buffer = malloc(s->input_control_buffer_size);
                        if (!s->input_control_buffer)
                                return -ENOMEM;
                }

                mh = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = s->input_control_buffer,
                        .msg_controllen = s->input_control_buffer_size,
                };

                n = RET_NERRNO(recvmsg(s->input_fd, &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC));
                if (n >= 0 && FLAGS_SET(mh.msg_flags, MSG_TRUNC)) {
                        cmsg_close_all(&mh);
                        return -EXFULL;
                }
                if (n >= 0 && FLAGS_SET(mh.msg_flags, MSG_CTRUNC)) {
                        /* SCM_RIGHTS got truncated — typically because an LSM (e.g. SELinux)
                         * denied the fd transfer. Drop the partial fds and continue with the
                         * data bytes: the request handler will surface a clean error to the
                         * peer when it tries to peek the missing fd, instead of us tearing
                         * the connection down silently and leaving the caller waiting. */
                        json_stream_log(s, "SCM_RIGHTS truncated on inbound message, dropping received file descriptors.");
                        cmsg_close_all(&mh);
                        mh.msg_controllen = 0;
                }
        } else if (FLAGS_SET(s->flags, JSON_STREAM_PREFER_READ))
                n = RET_NERRNO(read(s->input_fd, p, rs));
        else
                n = RET_NERRNO(recv(s->input_fd, p, rs, MSG_DONTWAIT));
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        if (ERRNO_IS_NEG_DISCONNECT(n)) {
                s->flags |= JSON_STREAM_READ_DISCONNECTED;
                return 1;
        }
        if (n < 0)
                return n;
        if (n == 0) { /* EOF */
                if (FLAGS_SET(s->flags, JSON_STREAM_ALLOW_FD_PASSING_INPUT))
                        cmsg_close_all(&mh);

                s->flags |= JSON_STREAM_READ_DISCONNECTED;
                return 1;
        }

        if (FLAGS_SET(s->flags, JSON_STREAM_ALLOW_FD_PASSING_INPUT)) {
                struct cmsghdr *cmsg;

                cmsg = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1);
                if (cmsg) {
                        size_t add;

                        /* fds are only allowed with the first byte of a message; receiving them
                         * mid-stream is a protocol violation. */
                        if (s->input_buffer_size != 0) {
                                cmsg_close_all(&mh);
                                return -EPROTO;
                        }

                        add = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        if (add > INT_MAX - s->n_input_fds) {
                                cmsg_close_all(&mh);
                                return -EBADF;
                        }

                        if (!GREEDY_REALLOC(s->input_fds, s->n_input_fds + add)) {
                                cmsg_close_all(&mh);
                                return -ENOMEM;
                        }

                        memcpy_safe(s->input_fds + s->n_input_fds, CMSG_TYPED_DATA(cmsg, int), add * sizeof(int));
                        s->n_input_fds += add;
                }
        }

        /* Also rescan the last delimiter_size - 1 bytes already buffered, so a delimiter split
         * across reads can be found. */
        size_t rescan = MIN(s->input_buffer_size, json_stream_delimiter_size(s) - 1);

        s->input_buffer_size += n;
        s->input_buffer_unscanned = rescan + n;

        return 1;
}

/* ===== Parse ===== */

int json_stream_parse(JsonStream *s, sd_json_variant **ret) {
        char *begin, *e;
        size_t sz;
        int r;

        assert(s);
        assert(ret);

        if (s->input_buffer_unscanned == 0) {
                *ret = NULL;
                return 0;
        }

        assert(s->input_buffer_unscanned <= s->input_buffer_size);
        assert(s->input_buffer_index + s->input_buffer_size <= MALLOC_SIZEOF_SAFE(s->input_buffer));

        begin = s->input_buffer + s->input_buffer_index;

        size_t dsz = json_stream_delimiter_size(s);
        e = memmem_safe(begin + s->input_buffer_size - s->input_buffer_unscanned, s->input_buffer_unscanned, s->delimiter ?: "\0", dsz);
        if (!e) {
                s->input_buffer_unscanned = 0;
                *ret = NULL;
                return 0;
        }

        sz = e - begin + dsz;

        /* For non-NUL delimiters (e.g. "\r\n" for QMP) sd_json_parse() needs a NUL-terminated
         * string; overwrite the first delimiter byte with NUL in place. For NUL delimiters
         * this is a no-op since the byte is already '\0'. */
        if (s->delimiter)
                *e = '\0';

        r = sd_json_parse(begin, SD_JSON_PARSE_MUST_BE_OBJECT, ret, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (FLAGS_SET(s->flags, JSON_STREAM_INPUT_SENSITIVE))
                explicit_bzero_safe(begin, sz);
        if (r < 0) {
                /* Unrecoverable parse failure: drop all buffered data. */
                s->input_buffer_index = s->input_buffer_size = s->input_buffer_unscanned = 0;
                return json_stream_log_errno(s, r, "Failed to parse JSON object: %m");
        }

        if (DEBUG_LOGGING) {
                _cleanup_(erase_and_freep) char *censored_text = NULL;

                /* Suppress sensitive fields in the debug output */
                r = sd_json_variant_format(*ret, /* flags= */ SD_JSON_FORMAT_CENSOR_SENSITIVE, &censored_text);
                if (r >= 0)
                        json_stream_log(s, "Received message: %s", censored_text);
        }

        s->input_buffer_size -= sz;

        if (s->input_buffer_size == 0)
                s->input_buffer_index = 0;
        else
                s->input_buffer_index += sz;

        s->input_buffer_unscanned = s->input_buffer_size;
        return 1;
}

/* ===== Serialization ===== */

static int json_stream_serialize_fd(int fd, int **fds, size_t *n_fds, sd_json_variant **ret) {
        assert(fds);
        assert(n_fds);
        assert(ret);

        /* Duplicates the fd, appends the copy to the fds array, and returns its index as JSON. Already
         * taken fds (i.e. negative ones) are serialized as null, so that the indexes of the others don't
         * change. */

        if (fd < 0)
                return sd_json_variant_new_null(ret);

        if (!GREEDY_REALLOC(*fds, *n_fds + 1))
                return -ENOMEM;

        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        (*fds)[(*n_fds)++] = copy;
        return sd_json_variant_new_unsigned(ret, *n_fds - 1);
}

static int json_stream_serialize_fd_array(const int *array, size_t n, int **fds, size_t *n_fds, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
        int r;

        assert(array || n == 0);
        assert(ret);

        FOREACH_ARRAY(i, array, n) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *e = NULL;

                r = json_stream_serialize_fd(*i, fds, n_fds, &e);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&a, e);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(a);
        return 0;
}

static int json_stream_serialize_buffer(const char *buffer, size_t index, size_t n, bool sensitive, sd_json_variant **ret) {
        int r;

        assert(buffer || n == 0);
        assert(ret);

        /* Don't calculate buffer + index if there's nothing to serialize, the buffer might be NULL */
        if (n == 0) {
                *ret = NULL;
                return 0;
        }

        r = sd_json_variant_new_base64(ret, buffer + index, n);
        if (r < 0)
                return r;

        if (sensitive)
                sd_json_variant_sensitive(*ret);

        return 0;
}

int json_stream_serialize(const JsonStream *s, sd_json_variant **ret, int **fds, size_t *n_fds) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant
                *input_fd = NULL, *output_fd = NULL,
                *input_buffer = NULL, *output_buffer = NULL,
                *input_fds = NULL, *output_fds = NULL,
                *peer_pidfd = NULL, *queue = NULL;
        int r;

        assert(s);
        assert(ret);
        assert(fds);
        assert(n_fds);

        if (s->input_fd < 0 || s->output_fd < 0)
                return -ENOTCONN;

        r = json_stream_serialize_fd(s->input_fd, fds, n_fds, &input_fd);
        if (r < 0)
                return r;

        if (s->output_fd == s->input_fd)
                output_fd = sd_json_variant_ref(input_fd);
        else {
                r = json_stream_serialize_fd(s->output_fd, fds, n_fds, &output_fd);
                if (r < 0)
                        return r;
        }

        /* Pass on the peer pidfd if we have one. While the peer is alive, a new pidfd could be acquired
         * any time, but once it died that's not possible anymore, and a pidfd referring to a dead
         * process is still useful (for example to recognize that it died). */
        if (s->peer_pidfd >= 0) {
                r = json_stream_serialize_fd(s->peer_pidfd, fds, n_fds, &peer_pidfd);
                if (r < 0)
                        return r;
        }

        r = json_stream_serialize_buffer(
                        s->input_buffer,
                        s->input_buffer_index,
                        s->input_buffer_size,
                        /* sensitive= */ FLAGS_SET(s->flags, JSON_STREAM_INPUT_SENSITIVE),
                        &input_buffer);
        if (r < 0)
                return r;

        r = json_stream_serialize_buffer(
                        s->output_buffer,
                        s->output_buffer_index,
                        s->output_buffer_size,
                        /* sensitive= */ FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE),
                        &output_buffer);
        if (r < 0)
                return r;

        r = json_stream_serialize_fd_array(s->input_fds, s->n_input_fds, fds, n_fds, &input_fds);
        if (r < 0)
                return r;

        r = json_stream_serialize_fd_array(s->output_fds, s->n_output_fds, fds, n_fds, &output_fds);
        if (r < 0)
                return r;

        LIST_FOREACH(queue, q, s->output_queue) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *qfds = NULL;

                r = json_stream_serialize_fd_array(q->fds, q->n_fds, fds, n_fds, &qfds);
                if (r < 0)
                        return r;

                /* Sensitivity is not retained by the formatted JSON, hence remember it explicitly */
                r = sd_json_variant_append_arraybo(
                                &queue,
                                SD_JSON_BUILD_PAIR_VARIANT("message", q->data),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("fds", qfds),
                                JSON_BUILD_PAIR_CONDITION_BOOLEAN(sd_json_variant_is_sensitive_recursive(q->data), "sensitive", true));
                if (r < 0)
                        return r;
        }

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_VARIANT("inputFd", input_fd),
                        SD_JSON_BUILD_PAIR_VARIANT("outputFd", output_fd),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(FLAGS_SET(s->flags, JSON_STREAM_CONNECTING), "connecting", true),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(FLAGS_SET(s->flags, JSON_STREAM_READ_DISCONNECTED), "readDisconnected", true),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(FLAGS_SET(s->flags, JSON_STREAM_WRITE_DISCONNECTED), "writeDisconnected", true),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(FLAGS_SET(s->flags, JSON_STREAM_GOT_POLLHUP), "gotPollHup", true),
                        JSON_BUILD_PAIR_CONDITION_BOOLEAN(FLAGS_SET(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE), "outputBufferSensitive", true),
                        JSON_BUILD_PAIR_FINITE_USEC("lastActivityUSec", s->last_activity),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        s->ucred_acquired && s->ucred_overridden,
                                        "overrideUcred",
                                        SD_JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(pid_is_valid(s->ucred.pid), "pid", s->ucred.pid),
                                                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(uid_is_valid(s->ucred.uid), "uid", s->ucred.uid),
                                                        JSON_BUILD_PAIR_CONDITION_UNSIGNED(gid_is_valid(s->ucred.gid), "gid", s->ucred.gid))),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("peerPidfd", peer_pidfd),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("inputBuffer", input_buffer),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("inputFds", input_fds),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("outputBuffer", output_buffer),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("outputFds", output_fds),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("outputQueue", queue));
}

static int json_stream_deserialize_fd(sd_json_variant *v, const int *fds, size_t n_fds, int *ret) {
        assert(fds || n_fds == 0);
        assert(ret);

        if (sd_json_variant_is_null(v)) {
                *ret = -EBADF;
                return 0;
        }

        if (!sd_json_variant_is_unsigned(v))
                return -EINVAL;

        uint64_t i = sd_json_variant_unsigned(v);
        if (i >= n_fds || fds[i] < 0)
                return -EBADF;

        int copy = fcntl(fds[i], F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        *ret = copy;
        return 0;
}

static int json_stream_deserialize_fd_array(sd_json_variant *v, const int *fds, size_t n_fds, int **ret, size_t *ret_n) {
        int *array = NULL;
        size_t n = 0;
        int r;

        assert(ret);
        assert(ret_n);

        CLEANUP_ARRAY(array, n, close_many_and_free);

        if (!v || sd_json_variant_is_blank_array(v)) {
                *ret = NULL;
                *ret_n = 0;
                return 0;
        }

        if (!sd_json_variant_is_array(v))
                return -EINVAL;

        array = new(int, sd_json_variant_elements(v));
        if (!array)
                return -ENOMEM;

        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                r = json_stream_deserialize_fd(e, fds, n_fds, array + n);
                if (r < 0)
                        return r;

                n++;
        }

        *ret = TAKE_PTR(array);
        *ret_n = TAKE_GENERIC(n, size_t, 0);
        return 0;
}

static int json_stream_deserialize_buffer(sd_json_variant *v, size_t max, struct iovec *ret) {
        _cleanup_(iovec_done_erase) struct iovec iov = {};
        size_t l;
        int r;

        assert(ret);

        if (!v) {
                *ret = (struct iovec) {};
                return 0;
        }

        if (!sd_json_variant_is_string(v))
                return -EINVAL;

        /* Refuse oversized buffers before decoding them: the Base64 encoding of max bytes (with padding,
         * which is how we encode them) is 4 * DIV_ROUND_UP(max, 3) characters long. */
        const char *s = sd_json_variant_string(v);
        l = strlen(s);
        if (l / 4 > DIV_ROUND_UP(max, 3))
                return -ENOBUFS;

        /* The buffers might contain sensitive data, hence decode them in secure mode */
        r = unbase64mem_full(s, l, /* secure= */ true, &iov.iov_base, &iov.iov_len);
        if (r < 0)
                return r;

        if (iov.iov_len > max)
                return -ENOBUFS;

        *ret = TAKE_STRUCT(iov);
        return 0;
}

typedef struct JsonStreamSerializedQueueItem {
        sd_json_variant *message;
        sd_json_variant *fds;
        bool sensitive;
} JsonStreamSerializedQueueItem;

static int json_stream_deserialize_queue(JsonStream *s, sd_json_variant *v, const int *fds, size_t n_fds) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "message",   SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, offsetof(JsonStreamSerializedQueueItem, message),   SD_JSON_MANDATORY },
                { "fds",       SD_JSON_VARIANT_ARRAY,  sd_json_dispatch_variant_noref, offsetof(JsonStreamSerializedQueueItem, fds),       0                 },
                { "sensitive", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(JsonStreamSerializedQueueItem, sensitive), 0                 },
                {}
        };
        int r;

        assert(s);

        if (!v)
                return 0;

        if (!sd_json_variant_is_array(v))
                return -EINVAL;

        sd_json_variant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                JsonStreamSerializedQueueItem item = {};

                if (s->n_output_queue >= s->queue_max)
                        return -ENOBUFS;

                r = sd_json_dispatch(e, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &item);
                if (r < 0)
                        return r;

                int *item_fds = NULL;
                size_t n_item_fds = 0;
                CLEANUP_ARRAY(item_fds, n_item_fds, close_many_and_free);

                r = json_stream_deserialize_fd_array(item.fds, fds, n_fds, &item_fds, &n_item_fds);
                if (r < 0)
                        return r;

                if (item.sensitive)
                        sd_json_variant_sensitive(item.message);

                JsonStreamQueueItem *q = json_stream_queue_item_new(item.message, item_fds, n_item_fds);
                if (!q)
                        return -ENOMEM;

                /* The fds are owned by the queue item now */
                n_item_fds = 0;
                item_fds = mfree(item_fds);

                LIST_INSERT_AFTER(queue, s->output_queue, s->output_queue_tail, q);
                s->output_queue_tail = q;
                s->n_output_queue++;
        }

        return 0;
}

typedef struct JsonStreamSerialization {
        sd_json_variant *input_fd;
        sd_json_variant *output_fd;
        bool connecting;
        bool read_disconnected;
        bool write_disconnected;
        bool got_pollhup;
        bool output_buffer_sensitive;
        usec_t last_activity;
        sd_json_variant *override_ucred;
        sd_json_variant *peer_pidfd;
        sd_json_variant *input_buffer;
        sd_json_variant *input_fds;
        sd_json_variant *output_buffer;
        sd_json_variant *output_fds;
        sd_json_variant *output_queue;
} JsonStreamSerialization;

int json_stream_deserialize(JsonStream *s, sd_json_variant *v, const int *fds, size_t n_fds) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "inputFd",               _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, input_fd),                SD_JSON_MANDATORY },
                { "outputFd",              _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, output_fd),               SD_JSON_MANDATORY },
                { "connecting",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(JsonStreamSerialization, connecting),              0                 },
                { "readDisconnected",      SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(JsonStreamSerialization, read_disconnected),       0                 },
                { "writeDisconnected",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(JsonStreamSerialization, write_disconnected),      0                 },
                { "gotPollHup",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(JsonStreamSerialization, got_pollhup),             0                 },
                { "outputBufferSensitive", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       offsetof(JsonStreamSerialization, output_buffer_sensitive), 0                 },
                { "lastActivityUSec",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,        offsetof(JsonStreamSerialization, last_activity),           0                 },
                { "overrideUcred",         SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, override_ucred),          0                 },
                { "peerPidfd",             SD_JSON_VARIANT_UNSIGNED,      sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, peer_pidfd),              0                 },
                { "inputBuffer",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, input_buffer),            0                 },
                { "inputFds",              SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, input_fds),               0                 },
                { "outputBuffer",          SD_JSON_VARIANT_STRING,        sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, output_buffer),           0                 },
                { "outputFds",             SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, output_fds),              0                 },
                { "outputQueue",           SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_variant_noref, offsetof(JsonStreamSerialization, output_queue),            0                 },
                {}
        };

        _cleanup_(iovec_done_erase) struct iovec input_buffer = {}, output_buffer = {};
        JsonStreamSerialization p = {
                .last_activity = USEC_INFINITY,
        };
        int r;

        assert(s);
        assert(s->input_fd < 0);
        assert(s->output_fd < 0);
        assert(v);

        /* Unknown fields are ignored, so that the consumer can store its own data in the same object, and to
         * handle serializations from newer versions gracefully. */
        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return r;

        r = json_stream_deserialize_buffer(p.input_buffer, s->buffer_max, &input_buffer);
        if (r < 0)
                return r;

        r = json_stream_deserialize_buffer(p.output_buffer, s->buffer_max, &output_buffer);
        if (r < 0)
                return r;

        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        r = json_stream_deserialize_fd(p.input_fd, fds, n_fds, &input_fd);
        if (r < 0)
                return r;
        if (input_fd < 0)
                return -EBADF;

        if (sd_json_variant_equal(p.input_fd, p.output_fd))
                r = json_stream_attach_fds(s, input_fd, input_fd);
        else {
                r = json_stream_deserialize_fd(p.output_fd, fds, n_fds, &output_fd);
                if (r < 0)
                        return r;
                if (output_fd < 0)
                        return -EBADF;

                r = json_stream_attach_fds(s, input_fd, output_fd);
        }
        if (r < 0)
                return r;

        TAKE_FD(input_fd);
        TAKE_FD(output_fd);

        /* Set the runtime flags only after attaching the fds, since that recomputes the read/write
         * preference flags (which are not serialized) */
        SET_FLAG(s->flags, JSON_STREAM_CONNECTING, p.connecting);
        SET_FLAG(s->flags, JSON_STREAM_READ_DISCONNECTED, p.read_disconnected);
        SET_FLAG(s->flags, JSON_STREAM_WRITE_DISCONNECTED, p.write_disconnected);
        SET_FLAG(s->flags, JSON_STREAM_GOT_POLLHUP, p.got_pollhup);

        s->last_activity = p.last_activity;

        if (p.override_ucred) {
                static const sd_json_dispatch_field ucred_dispatch_table[] = {
                        { "pid", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,   offsetof(struct ucred, pid), 0 },
                        { "uid", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, offsetof(struct ucred, uid), 0 },
                        { "gid", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, offsetof(struct ucred, gid), 0 },
                        {}
                };
                struct ucred ucred = UCRED_INVALID;

                assert_cc(sizeof(pid_t) == sizeof(int32_t));

                r = sd_json_dispatch(p.override_ucred, ucred_dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &ucred);
                if (r < 0)
                        return r;

                /* The PID is optional, but if it is specified it must be valid */
                if (ucred.pid != 0 && !pid_is_valid(ucred.pid))
                        return -EINVAL;

                json_stream_set_peer_ucred(s, &ucred, /* overridden= */ true);
        }

        if (p.peer_pidfd) {
                r = json_stream_deserialize_fd(p.peer_pidfd, fds, n_fds, &s->peer_pidfd);
                if (r < 0)
                        return r;

                /* Make sure this is actually a pidfd. Note that the peer might have died in the
                 * meantime, or might live in a PID namespace we cannot see, which is fine. */
                r = pidfd_get_pid(s->peer_pidfd, /* ret= */ NULL);
                if (r < 0 && !IN_SET(r, -ESRCH, -EREMOTE))
                        return r;
        }

        r = json_stream_deserialize_fd_array(p.input_fds, fds, n_fds, &s->input_fds, &s->n_input_fds);
        if (r < 0)
                return r;

        r = json_stream_deserialize_fd_array(p.output_fds, fds, n_fds, &s->output_fds, &s->n_output_fds);
        if (r < 0)
                return r;

        /* fds are only sent along with the first byte of the output buffer */
        if (s->n_output_fds > 0 && output_buffer.iov_len == 0)
                return -EINVAL;

        if (input_buffer.iov_len > 0) {
                s->input_buffer = TAKE_PTR(input_buffer.iov_base);
                s->input_buffer_size = s->input_buffer_unscanned = TAKE_GENERIC(input_buffer.iov_len, size_t, 0);
        }

        if (output_buffer.iov_len > 0) {
                s->output_buffer = TAKE_PTR(output_buffer.iov_base);
                s->output_buffer_size = TAKE_GENERIC(output_buffer.iov_len, size_t, 0);
                SET_FLAG(s->flags, JSON_STREAM_OUTPUT_BUFFER_SENSITIVE, p.output_buffer_sensitive);
        }

        return json_stream_deserialize_queue(s, p.output_queue, fds, n_fds);
}
