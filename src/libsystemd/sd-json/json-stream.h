/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "sd-forward.h"

#include "list.h"
#include "log.h"

/* JsonStream provides the transport layer used by sd-varlink (and other consumers like
 * the QMP client) for exchanging length-delimited JSON messages over a pair of file
 * descriptors. It owns the input/output buffers, the file-descriptor passing machinery
 * (SCM_RIGHTS), the deferred output queue, and the read/write/parse step functions. It
 * does not implement any state machine, dispatch, callback or event-source plumbing —
 * those concerns belong to the consumer. */

typedef struct JsonStreamQueueItem JsonStreamQueueItem;

typedef enum JsonStreamFlags {
        JSON_STREAM_BOUNDED_READS           = 1u << 0,
        JSON_STREAM_INPUT_SENSITIVE         = 1u << 1,
        JSON_STREAM_ALLOW_FD_PASSING_INPUT  = 1u << 2,
        JSON_STREAM_ALLOW_FD_PASSING_OUTPUT = 1u << 3,
        JSON_STREAM_CONNECTING              = 1u << 4,
        JSON_STREAM_GOT_POLLHUP             = 1u << 5,
        JSON_STREAM_WRITE_DISCONNECTED      = 1u << 6,
        JSON_STREAM_READ_DISCONNECTED       = 1u << 7,
        JSON_STREAM_PREFER_READ             = 1u << 8,
        JSON_STREAM_PREFER_WRITE            = 1u << 9,
        JSON_STREAM_OUTPUT_BUFFER_SENSITIVE = 1u << 10,
} JsonStreamFlags;

/* What the consumer's high-level state machine is currently doing — used by the various
 * "what should I do right now?" APIs (get_events, wait, should_disconnect) to decide
 * whether to ask for read events, whether transport death matters, and whether the idle
 * timeout deadline is currently in force. */
typedef enum JsonStreamPhase {
        JSON_STREAM_PHASE_READING,         /* waiting for the next inbound message, no deadline */
        JSON_STREAM_PHASE_AWAITING_REPLY,  /* waiting for a reply with the idle timeout deadline */
        JSON_STREAM_PHASE_IDLE_CLIENT,     /* idle client, no in-flight call */
        JSON_STREAM_PHASE_PENDING_OUTPUT,  /* has more output queued, waiting to send */
        JSON_STREAM_PHASE_OTHER,           /* none of the above */
} JsonStreamPhase;

/* Consumer hooks supplied at construction time:
 *   • phase     — queried by get_events / wait / should_disconnect / attach_event's prepare
 *                 callback whenever the consumer's current phase is needed.
 *   • dispatch  — invoked by attach_event's io and time callbacks after the stream has
 *                 consumed the revents, so the consumer can drive its state machine
 *                 forward. Should return 0 on success or a negative errno; the stream logs
 *                 the failure and continues running. */
typedef JsonStreamPhase (*json_stream_phase_t)(void *userdata);
typedef int (*json_stream_dispatch_t)(void *userdata);

typedef struct JsonStreamParams {
        const char *delimiter;  /* message delimiter; NULL → single NUL byte (varlink), e.g. "\r\n" for QMP */
        size_t buffer_max;      /* maximum bytes buffered before -ENOBUFS; 0 = 16 MiB default */
        size_t read_chunk;      /* per-read chunk size; 0 = 64 KiB default */
        size_t queue_max;       /* maximum number of queued output items; 0 = 64 Ki default */

        /* Consumer hooks (see typedefs above). */
        json_stream_phase_t phase;
        json_stream_dispatch_t dispatch;
        void *userdata;
} JsonStreamParams;

typedef struct JsonStream {
        char *delimiter;         /* message delimiter; NULL → NUL byte (varlink), e.g. "\r\n" for QMP */
        size_t buffer_max;
        size_t read_chunk;
        size_t queue_max;

        char *description;

        int input_fd;
        int output_fd;

        usec_t timeout;          /* relative; USEC_INFINITY = no timeout */
        usec_t last_activity;    /* CLOCK_MONOTONIC */

        /* Cached peer credentials */
        struct ucred ucred;
        bool ucred_acquired;
        int peer_pidfd;

        /* Cached socket address family. -1 = unchecked, AF_UNSPEC = checked-not-socket,
         * otherwise the resolved family. */
        int af;

        sd_event *event;
        sd_event_source *input_event_source;
        sd_event_source *output_event_source;
        sd_event_source *time_event_source;

        json_stream_phase_t phase_cb;
        json_stream_dispatch_t dispatch_cb;
        void *userdata;

        char *input_buffer;
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned;

        void *input_control_buffer;
        size_t input_control_buffer_size;

        char *output_buffer;
        size_t output_buffer_index;
        size_t output_buffer_size;

        int *input_fds;
        size_t n_input_fds;

        int *output_fds;
        size_t n_output_fds;

        LIST_HEAD(JsonStreamQueueItem, output_queue);
        JsonStreamQueueItem *output_queue_tail;
        size_t n_output_queue;

        int *pushed_fds;
        size_t n_pushed_fds;

        JsonStreamFlags flags;
} JsonStream;

int json_stream_init(JsonStream *s, const JsonStreamParams *params);
void json_stream_done(JsonStream *s);

/* Optional description used as the prefix for the stream's debug log lines (sent/received
 * messages, POLLHUP detection, async connect completion, etc.). The string is duped. */
int json_stream_set_description(JsonStream *s, const char *description);
const char* json_stream_get_description(const JsonStream *s);

static inline const char* json_stream_description(const JsonStream *s) {
        return (s ? s->description : NULL) ?: "json-stream";
}

#define json_stream_log(s, fmt, ...) \
        log_debug("%s: " fmt, json_stream_description(s), ##__VA_ARGS__)

#define json_stream_log_errno(s, error, fmt, ...) \
        log_debug_errno((error), "%s: " fmt, json_stream_description(s), ##__VA_ARGS__)

/* fd ownership */
int json_stream_attach_fds(JsonStream *s, int input_fd, int output_fd);

/* Open an AF_UNIX SOCK_STREAM socket and connect to the given filesystem path, attaching
 * the resulting fd to the stream. Handles paths too long for sockaddr_un by routing through
 * O_PATH (connect_unix_path()). If the connect() returns EAGAIN/EINPROGRESS the stream's
 * connecting state is set so that the consumer waits for POLLOUT before treating the
 * connection as established. Returns 0 on success or successfully started async connect,
 * negative errno on failure. */
int json_stream_connect_address(JsonStream *s, const char *address);

/* Adopt a pre-connected pair of fds, ensuring both are non-blocking. Equivalent to
 * json_stream_attach_fds() but does the fd_nonblock() dance up front, so the caller can
 * pass in fds without having to know whether they were already configured. */
int json_stream_connect_fd_pair(JsonStream *s, int input_fd, int output_fd);

bool json_stream_flags_set(const JsonStream *s, JsonStreamFlags flags);
void json_stream_set_flags(JsonStream *s, JsonStreamFlags flags, bool b);

/* Combines the transport-level disconnect signals (write/read disconnected, buffered
 * output, POLLHUP, async connect) with the consumer's current phase (queried via the
 * registered get_phase callback) to answer "should the consumer initiate teardown right
 * now?". The decision logic mirrors what the original varlink transport did but stays
 * generic enough for other JSON-line consumers. */
bool json_stream_should_disconnect(const JsonStream *s);

/* Enable/disable fd passing. These verify the underlying fd is an AF_UNIX socket and
 * (for input) optionally set SO_PASSRIGHTS. */
int json_stream_set_allow_fd_passing_input(JsonStream *s, bool enabled, bool with_sockopt);
int json_stream_set_allow_fd_passing_output(JsonStream *s, bool enabled);

/* Output: enqueue a JSON variant. Fast path concatenates into the output buffer; if
 * pushed_fds are present or the queue is non-empty the message is queued instead, so that
 * fd-to-message boundaries are preserved. */
int json_stream_enqueue(JsonStream *s, sd_json_variant *m);

/* Allocate a queue item carrying `m` and the currently pushed fds. The pushed fds are
 * transferred to the new item; on success n_pushed_fds is reset to 0. The caller may
 * later submit the item via json_stream_enqueue_item() or free it. */
int json_stream_make_queue_item(JsonStream *s, sd_json_variant *m, JsonStreamQueueItem **ret);
int json_stream_enqueue_item(JsonStream *s, JsonStreamQueueItem *q);
JsonStreamQueueItem* json_stream_queue_item_free(JsonStreamQueueItem *q);
DEFINE_TRIVIAL_CLEANUP_FUNC(JsonStreamQueueItem*, json_stream_queue_item_free);
sd_json_variant** json_stream_queue_item_get_data(JsonStreamQueueItem *q);

/* fd push/peek/take */
int json_stream_push_fd(JsonStream *s, int fd);
void json_stream_reset_pushed_fds(JsonStream *s);

int json_stream_peek_input_fd(const JsonStream *s, size_t i);
int json_stream_take_input_fd(JsonStream *s, size_t i);
size_t json_stream_get_n_input_fds(const JsonStream *s);

/* Close and free all currently received input fds (used after consuming a message). */
void json_stream_close_input_fds(JsonStream *s);

/* I/O steps. Same return-value contract as the original varlink_{write,read,parse_message}:
 *   1 = made progress (call again),
 *   0 = nothing to do (wait for I/O),
 *  <0 = error. */
int json_stream_write(JsonStream *s);
int json_stream_read(JsonStream *s);

/* Extract the next complete JSON message from the input buffer (delimited per
 * params.delimiter). Returns 1 with *ret set on success, 0 if no full message is
 * available yet (with *ret == NULL), <0 on parse error. The buffer slot occupied by the
 * parsed message is erased if input_sensitive was set. */
int json_stream_parse(JsonStream *s, sd_json_variant **ret);

/* Status accessors used by the consumer's state machine. */
bool json_stream_has_buffered_input(const JsonStream *s);

/* Compute the poll events the consumer should wait for. The stream queries the consumer's
 * phase via the registered get_phase callback. In JSON_STREAM_PHASE_READING the stream asks
 * for POLLIN (provided the input buffer is empty and the read side is still alive); POLLOUT
 * is added whenever there's pending output. When connecting we only ask for POLLOUT to
 * learn when the non-blocking connect() completes. */
int json_stream_get_events(const JsonStream *s);

/* Block on poll() for the configured fds for at most `timeout` µs. Internally updates the
 * connecting / got_pollhup state based on the seen revents.
 *   1 = some event was observed (call us again),
 *   0 = timeout,
 *  <0 = error (negative errno from ppoll_usec). */
int json_stream_wait(JsonStream *s, usec_t timeout);

/* Block until the output buffer is fully drained (or the write side disconnects).
 *   1 = some bytes were written during the flush,
 *   0 = nothing to flush,
 *  -ECONNRESET if the write side became disconnected before everything could be sent,
 *  <0 on other I/O errors. */
int json_stream_flush(JsonStream *s);

/* Peer credential helpers. All refuse if the stream uses different input/output fds, since
 * peer credentials are only meaningful for a bidirectional socket.
 *   • acquire_peer_uid/gid/pid/pidfd() query the kernel on first use, cache the result,
 *     and log failures (using the stream's description). They each return 0 on success
 *     with the value in *ret, or a negative errno on failure (kernel error or invalid
 *     field).
 *   • get_peer_ucred() returns the *already-cached* ucred (set via a prior acquire or via
 *     set_peer_ucred()) without triggering a kernel query — returns -ENODATA if nothing is
 *     cached. Used by consumers that want to react to a previously-known ucred without
 *     forcing a fresh query (e.g. teardown bookkeeping). */
int json_stream_acquire_peer_uid(JsonStream *s, uid_t *ret);
int json_stream_acquire_peer_gid(JsonStream *s, gid_t *ret);
int json_stream_acquire_peer_pid(JsonStream *s, pid_t *ret);
int json_stream_acquire_peer_pidfd(JsonStream *s);
int json_stream_get_peer_ucred(const JsonStream *s, struct ucred *ret);
void json_stream_set_peer_ucred(JsonStream *s, const struct ucred *ucred);

/* Per-operation idle timeout. The deadline is computed as last_activity + timeout.
 * Successful writes refresh last_activity automatically; the consumer should also call
 * json_stream_mark_activity() at operation start (e.g. when initiating a method call) to
 * reset the deadline.
 *
 * When the deadline elapses the time event source attached via json_stream_attach_event()
 * fires and the consumer's dispatch callback is invoked. The consumer detects the timeout
 * by comparing now(CLOCK_MONOTONIC) against json_stream_get_timeout(). */
void json_stream_set_timeout(JsonStream *s, usec_t timeout);
void json_stream_mark_activity(JsonStream *s);

/* Returns the absolute deadline (in CLOCK_MONOTONIC microseconds) currently in force for
 * the consumer's phase, or USEC_INFINITY if no timeout applies (no timeout configured, no
 * activity yet, or the current phase isn't AWAITING_REPLY). */
usec_t json_stream_get_timeout(const JsonStream *s);

/* sd-event integration. JsonStream owns the input/output io event sources and the time
 * event source for its idle timeout, and installs its own internal prepare and io callbacks
 * on them. The hooks (get_phase, io_dispatch) supplied via JsonStreamParams at construction
 * are wired up automatically. */
int json_stream_attach_event(JsonStream *s, sd_event *event, int64_t priority);
void json_stream_detach_event(JsonStream *s);
sd_event* json_stream_get_event(const JsonStream *s);
