/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "hash-funcs.h"
#include "siphash24.h"
#include "io-util.h"
#include "iovec-util.h"
#include "list.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"

/* Match QEMU's own CHR_READ_BUF_LEN (include/chardev/char.h) for the per-read() chunk size.
 * Normal QMP responses are well under 4K; the largest message (query-qmp-schema, ~230K) is
 * only read once during the blocking handshake at startup, so the extra syscalls are negligible. */
#define QMP_READ_SIZE ((size_t) 4096)

/* Match VARLINK_BUFFER_MAX from sd-varlink.c — same defensive upper bound on accumulated input. */
#define QMP_BUFFER_MAX (16U * 1024U * 1024U)

/* Match VARLINK_QUEUE_MAX — upper bound on queued output items. */
#define QMP_QUEUE_MAX (64U * 1024U)

typedef struct QmpPendingCommand {
        uint64_t id;
        qmp_command_callback_t callback;
        void *userdata;
} QmpPendingCommand;

static void qmp_pending_command_hash_func(const QmpPendingCommand *p, struct siphash *state) {
        siphash24_compress_typesafe(p->id, state);
}

static int qmp_pending_command_compare_func(const QmpPendingCommand *a, const QmpPendingCommand *b) {
        return CMP(a->id, b->id);
}

DEFINE_PRIVATE_HASH_OPS(qmp_pending_command_hash_ops,
                        QmpPendingCommand, qmp_pending_command_hash_func, qmp_pending_command_compare_func);

typedef struct QmpOutputItem QmpOutputItem;
struct QmpOutputItem {
        LIST_FIELDS(QmpOutputItem, queue);
        char *data;
        size_t data_size;
        size_t data_offset;    /* bytes already sent from this item */
        size_t n_fds;
        int fds[];             /* flexible array -- FDs to send with this item's first byte */
};

struct QmpClient {
        unsigned n_ref;

        int fd;
        sd_event *event;
        sd_event_source *io_event_source;
        sd_event_source *defer_event_source;

        char *input_buffer;            /* valid data at input_buffer+input_buffer_index, length input_buffer_size */
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned; /* bytes not yet scanned for \n delimiter */

        uint64_t next_id;
        Hashmap *pending_commands;     /* id → QmpPendingCommand*, for async dispatch */

        qmp_event_callback_t event_callback;
        qmp_disconnect_callback_t disconnect_callback;
        void *userdata;

        char *description;

        LIST_HEAD(QmpOutputItem, output_queue);
        QmpOutputItem *output_queue_tail;
        size_t n_output_queue;

        char *output_buffer;           /* serialized data ready for write() */
        size_t output_buffer_index;
        size_t output_buffer_size;
        int *output_fds;               /* FDs to send via SCM_RIGHTS with the next write */
        size_t n_output_fds;

        unsigned next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

        int *pushed_fds;
        size_t n_pushed_fds;

        QmpClientState state;
        sd_json_variant *current;  /* pinned reply for blocking calls (like varlink's v->current) */
        uint64_t current_id;       /* id of the blocking call (to match the response) */


        bool write_disconnected;   /* write side hit a disconnect, wait for read to confirm */
};

/* Forward declaration — defined after io/defer callbacks */

/* Try to read available data from the fd into the buffer. Returns 1 if data was read, 0 if EAGAIN, negative on
 * error. Returns -ECONNRESET on EOF. Uses the varlink-style index+size buffer pattern to avoid memmove(). */
static int qmp_client_read(QmpClient *c) {
        ssize_t n;
        size_t rs;

        assert(c);

        if (c->input_buffer_size >= QMP_BUFFER_MAX)
                return -ENOBUFS;

        if (MALLOC_SIZEOF_SAFE(c->input_buffer) <= c->input_buffer_index + c->input_buffer_size) {
                size_t add;

                add = MIN(QMP_BUFFER_MAX - c->input_buffer_size, QMP_READ_SIZE);

                if (c->input_buffer_index == 0) {
                        if (!GREEDY_REALLOC(c->input_buffer, c->input_buffer_size + add))
                                return -ENOMEM;
                } else {
                        char *b;

                        b = new(char, c->input_buffer_size + add);
                        if (!b)
                                return -ENOMEM;

                        memcpy(b, c->input_buffer + c->input_buffer_index, c->input_buffer_size);
                        free_and_replace(c->input_buffer, b);
                        c->input_buffer_index = 0;
                }
        }

        rs = MALLOC_SIZEOF_SAFE(c->input_buffer) - (c->input_buffer_index + c->input_buffer_size);

        n = read(c->fd, c->input_buffer + c->input_buffer_index + c->input_buffer_size, rs);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return -EAGAIN;
                return -errno;
        }
        if (n == 0)
                return -ECONNRESET;

        c->input_buffer_size += n;
        c->input_buffer_unscanned += n;
        return 1;
}

/* Try to parse one complete QMP message from the buffer. QMP uses CRLF (\r\n) as the wire delimiter
 * (QEMU's monitor_puts converts \n to \r\n). We scan for \n as the message boundary; the preceding \r
 * is JSON whitespace and handled transparently by sd_json_parse(). We NUL-terminate the buffer at the
 * \n position so sd_json_parse() can work directly on it without copying — the same pattern varlink
 * uses for its \0-delimited messages. Returns 1 + parsed value in *ret if a complete message was found,
 * 0 if no complete message is available yet, negative on parse error. */
static int qmp_client_parse_message(QmpClient *c, sd_json_variant **ret) {
        char *begin, *e;
        size_t sz;
        int r;

        assert(c);
        assert(ret);

        if (c->input_buffer_unscanned == 0) {
                *ret = NULL;
                return 0;
        }

        assert(c->input_buffer_unscanned <= c->input_buffer_size);

        begin = c->input_buffer + c->input_buffer_index;

        e = memchr(begin + c->input_buffer_size - c->input_buffer_unscanned, '\n', c->input_buffer_unscanned);
        if (!e) {
                c->input_buffer_unscanned = 0;
                *ret = NULL;
                return 0;
        }

        sz = e - begin + 1;

        *e = '\0';

        r = sd_json_parse(begin, /* flags= */ 0, ret, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse QMP JSON message: %m");
                c->input_buffer_index = c->input_buffer_size = c->input_buffer_unscanned = 0;
                return r;
        }

        c->input_buffer_size -= sz;
        if (c->input_buffer_size == 0)
                c->input_buffer_index = 0;
        else
                c->input_buffer_index += sz;
        c->input_buffer_unscanned = c->input_buffer_size;

        return 1;
}

static void qmp_client_clear_current(QmpClient *c) {
        assert(c);

        c->current = sd_json_variant_unref(c->current);
}

int qmp_client_wait(QmpClient *c, usec_t timeout) {
        int r, events;

        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        events = qmp_client_get_events(c);
        if (events < 0)
                return events;

        r = fd_wait_for_event(c->fd, events, timeout);
        if (ERRNO_IS_NEG_TRANSIENT(r))
                return 1; /* Treat EINTR as "something might have happened", matching sd_varlink_wait() */
        if (r <= 0)
                return r;

        return 1;
}

static QmpOutputItem* qmp_output_item_free(QmpOutputItem *item) {
        if (!item)
                return NULL;
        close_many(item->fds, item->n_fds);
        free(item->data);
        return mfree(item);
}

/* Enqueue a JSON message (with any pushed FDs for SCM_RIGHTS) into the output queue.
 * Each queue item keeps its own data buffer and FDs together so that FD-to-message
 * associations are never mixed up. Actual I/O happens in qmp_client_write(). */
static int qmp_client_enqueue(QmpClient *c, sd_json_variant *v) {
        _cleanup_free_ char *json_str = NULL;
        size_t n_fds, len;
        QmpOutputItem *item;
        int r;

        assert(c);
        assert(v);

        if (c->n_output_queue >= QMP_QUEUE_MAX)
                return -ENOBUFS;

        r = sd_json_variant_format(v, SD_JSON_FORMAT_NEWLINE, &json_str);
        if (r < 0)
                return r;

        len = strlen(json_str);
        n_fds = c->n_pushed_fds;

        item = malloc(voffsetof(*item, fds) + sizeof(int) * n_fds);
        if (!item)
                return -ENOMEM;

        *item = (QmpOutputItem) {
                .data = TAKE_PTR(json_str),
                .data_size = len,
                .n_fds = n_fds,
        };

        if (n_fds > 0) {
                memcpy(item->fds, c->pushed_fds, sizeof(int) * n_fds);
                c->n_pushed_fds = 0; /* fds belong to queue item now, keep allocation for reuse */
        }

        LIST_INSERT_AFTER(queue, c->output_queue, c->output_queue_tail, item);
        c->output_queue_tail = item;
        c->n_output_queue++;

        return 0;
}


/* Drain queue items into the flat output buffer. Matching varlink_format_queue() 1:1:
 * if there are unsent FDs in the buffer, don't drain more (preserves FD/message boundary).
 * Otherwise drain items, moving their FDs to the connection-level output_fds. */
static int qmp_client_format_queue(QmpClient *c) {
        assert(c);

        while (c->output_queue) {
                assert(c->n_output_queue > 0);

                if (c->n_output_fds > 0) /* unsent FDs? adding more would corrupt boundaries */
                        return 0;

                QmpOutputItem *q = c->output_queue;
                _cleanup_free_ int *array = NULL;

                if (q->n_fds > 0) {
                        array = newdup(int, q->fds, q->n_fds);
                        if (!array)
                                return -ENOMEM;
                }

                /* Append item data to output buffer */
                size_t remaining = q->data_size - q->data_offset;
                if (!GREEDY_REALLOC(c->output_buffer, c->output_buffer_size + remaining))
                        return -ENOMEM;

                memcpy(c->output_buffer + c->output_buffer_size,
                       q->data + q->data_offset, remaining);
                c->output_buffer_size += remaining;

                /* Take possession of the queue item's FDs */
                free_and_replace(c->output_fds, array);
                c->n_output_fds = q->n_fds;
                q->n_fds = 0;

                LIST_REMOVE(queue, c->output_queue, q);
                if (!c->output_queue)
                        c->output_queue_tail = NULL;
                c->n_output_queue--;

                qmp_output_item_free(q);
        }

        return 0;
}

/* Send data from the output buffer. Matching varlink_write() 1:1. */
static int qmp_client_write(QmpClient *c) {
        ssize_t n;
        int r;

        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return 0;
        if (c->write_disconnected)
                return 0;

        r = qmp_client_format_queue(c);
        if (r < 0)
                return r;

        if (c->output_buffer_size == 0)
                return 0;

        if (c->n_output_fds > 0) {
                struct iovec iov = {
                        .iov_base = c->output_buffer + c->output_buffer_index,
                        .iov_len = c->output_buffer_size,
                };
                struct msghdr mh = {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_controllen = CMSG_SPACE(sizeof(int) * c->n_output_fds),
                };

                mh.msg_control = alloca0(mh.msg_controllen);

                struct cmsghdr *control = CMSG_FIRSTHDR(&mh);
                control->cmsg_len = CMSG_LEN(sizeof(int) * c->n_output_fds);
                control->cmsg_level = SOL_SOCKET;
                control->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(control), c->output_fds, sizeof(int) * c->n_output_fds);

                n = sendmsg(c->fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        } else
                n = write(c->fd,
                          c->output_buffer + c->output_buffer_index,
                          c->output_buffer_size);

        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        c->write_disconnected = true;
                        return 1;
                }

                return -errno;
        }

        c->output_buffer_size -= n;

        if (c->output_buffer_size == 0)
                c->output_buffer_index = 0;
        else
                c->output_buffer_index += n;

        /* Close FDs after any successful write, matching varlink_write() */
        close_many(c->output_fds, c->n_output_fds);
        c->n_output_fds = 0;

        return 1;
}

int qmp_client_get_events(QmpClient *c) {
        int events = 0;

        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        events |= POLLIN;

        if (c->output_buffer_size > 0 || c->output_queue)
                events |= POLLOUT;

        return events;
}

static void qmp_client_update_events(QmpClient *c) {
        assert(c);

        if (!c->io_event_source)
                return;

        int events = qmp_client_get_events(c);
        if (events >= 0)
                (void) sd_event_source_set_io_events(c->io_event_source, events);
}

static int qmp_client_dispatch_event(QmpClient *c, sd_json_variant *v) {
        int r;

        assert(c);
        assert(v);

        if (!c->event_callback)
                return 0;

        struct {
                const char *event;
                sd_json_variant *data;
        } p = {};

        static const sd_json_dispatch_field table[] = {
                { "event", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  voffsetof(p, event), SD_JSON_MANDATORY },
                { "data",  SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(p, data),  0                 },
                {},
        };

        r = sd_json_dispatch(v, table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0) {
                log_debug_errno(r, "Failed to dispatch QMP event, ignoring: %m");
                return 0;
        }

        r = c->event_callback(c, p.event, p.data, c->userdata);
        if (r < 0)
                log_debug_errno(r, "Event callback returned error, ignoring: %m");

        return 1;
}

/* Extract the human-readable description from a QMP error object. We intentionally ignore the
 * "class" field: QEMU deprecated meaningful error classes years ago and now returns "GenericError"
 * for virtually everything. Only the "desc" string carries useful diagnostic information. */
static char* qmp_extract_error_description(sd_json_variant *error) {
        assert(error);

        sd_json_variant *desc = sd_json_variant_by_key(error, "desc");
        return strdup(desc ? sd_json_variant_string(desc) : "unspecified error");
}

static int qmp_client_build_command(QmpClient *c, const char *command, sd_json_variant *arguments, sd_json_variant **ret, uint64_t *ret_id) {
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(ret);

        id = c->next_id++;

        r = sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_STRING("execute", command),
                        SD_JSON_BUILD_PAIR_CONDITION(!!arguments, "arguments", SD_JSON_BUILD_VARIANT(arguments)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", id));
        if (r < 0)
                return r;

        if (ret_id)
                *ret_id = id;

        return 0;
}

/* Send a synchronous QMP command and wait for the response (process+wait loop).
 * Matches sd_varlink_call(): returns borrowed references into the pinned c->current
 * (valid until the next call/close). If ret_error_desc is NULL and a QMP error occurs,
 * returns -EIO. If ret_error_desc is provided, returns 0 and lets the caller inspect. */
int qmp_client_call(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                const char **ret_error_desc) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        int r;

        assert(c);
        assert(command);
        assert(c->state == QMP_CLIENT_IDLE);

        /* Clear any pinned response from a previous call, matching varlink_clear_current() */
        qmp_client_clear_current(c);

        r = qmp_client_build_command(c, command, arguments, &cmd, &c->current_id);
        if (r < 0)
                return r;

        r = qmp_client_enqueue(c, cmd);
        if (r < 0)
                return r;

        c->state = QMP_CLIENT_CALLING;

        while (c->state == QMP_CLIENT_CALLING) {
                r = qmp_client_process(c);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = qmp_client_wait(c, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        switch (c->state) {

        case QMP_CLIENT_CALLED: {
                assert(c->current);

                /* Leave c->current pinned — return borrowed references into it,
                 * matching sd_varlink_call_full()'s pattern. */
                c->state = QMP_CLIENT_IDLE;

                sd_json_variant *e = sd_json_variant_by_key(c->current, "error"),
                                *p = sd_json_variant_by_key(c->current, "return");

                /* If caller doesn't ask for error string, return error code on failure */
                if (!ret_error_desc && e)
                        return -EIO;

                if (ret_result)
                        *ret_result = p;
                if (ret_error_desc) {
                        sd_json_variant *desc = e ? sd_json_variant_by_key(e, "desc") : NULL;
                        *ret_error_desc = desc ? sd_json_variant_string(desc) : NULL;
                }

                return 1;
        }

        case QMP_CLIENT_DISCONNECTED:
                return -ECONNRESET;

        default:
                assert_not_reached();
        }
}

/* Dispatch a parsed QMP message from c->current: route command responses to pending
 * async callbacks, and events to the event callback. Returns 1 on successful dispatch
 * to signal "work was done" to the process() loop — matching sd-varlink's
 * varlink_dispatch_reply() pattern. Callback errors are logged but not propagated. */
static int qmp_client_dispatch_reply(QmpClient *c) {
        sd_json_variant *id_variant;
        int r;

        assert(c);

        if (!c->current)
                return 0;

        /* Events have an "event" key */
        if (sd_json_variant_by_key(c->current, "event")) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                (void) qmp_client_dispatch_event(c, v);
                return 1;
        }

        /* Command responses have an "id" key — match against pending async commands */
        id_variant = sd_json_variant_by_key(c->current, "id");
        if (id_variant) {
                uint64_t id = sd_json_variant_unsigned(id_variant);

                /* If we're in a blocking call and this is the response we're waiting for,
                 * leave current pinned and transition to CALLED — matching
                 * varlink_dispatch_reply()'s handling of VARLINK_CALLING. */
                if (c->state == QMP_CLIENT_CALLING && id == c->current_id) {
                        c->state = QMP_CLIENT_CALLED;
                        return 1;
                }

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = TAKE_PTR(c->current);
                _cleanup_free_ QmpPendingCommand *pending = hashmap_remove(c->pending_commands, &(QmpPendingCommand) { .id = id });
                if (!pending) {
                        log_debug("Discarding unmatched QMP response for id %" PRIu64, id);
                        return 1;
                }

                sd_json_variant *result = sd_json_variant_by_key(v, "return");
                sd_json_variant *error = sd_json_variant_by_key(v, "error");
                _cleanup_free_ char *error_desc = error ? qmp_extract_error_description(error) : NULL;

                r = pending->callback(c,
                                      result,
                                      error_desc,
                                      result ? 0 : error ? -EIO : -EPROTO,
                                      pending->userdata);
                if (r < 0)
                        log_debug_errno(r, "Command callback returned error, ignoring: %m");

                return 1;
        }

        /* Unknown message — discard */
        qmp_client_clear_current(c);
        log_debug("Discarding unrecognized QMP message");
        return 0;
}

/* Fail all pending async commands with the given error. Called on disconnect. */
static void qmp_client_fail_pending(QmpClient *c, int error) {
        QmpPendingCommand *p;

        assert(c);

        while ((p = hashmap_steal_first(c->pending_commands))) {
                int r = p->callback(c, NULL, NULL, error, p->userdata);
                if (r < 0)
                        log_debug_errno(r, "Command callback returned error, ignoring: %m");
                free(p);
        }
}

/* Emit a synthetic SHUTDOWN event when the QMP connection drops unexpectedly. Ensures
 * subscribers learn the VM is gone even if QEMU crashed without sending a SHUTDOWN event
 * (inspired by Incus's synthetic shutdown pattern). */
static void qmp_client_emit_synthetic_shutdown(QmpClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *data = NULL;

        assert(c);

        if (!c->event_callback)
                return;

        (void) sd_json_buildo(
                        &data,
                        SD_JSON_BUILD_PAIR_BOOLEAN("guest", false),
                        SD_JSON_BUILD_PAIR_STRING("reason", "disconnected"));

        int r = c->event_callback(c, "SHUTDOWN", data, c->userdata);
        if (r < 0)
                log_debug_errno(r, "Event callback returned error, ignoring: %m");
}

static int qmp_client_handle_disconnect(QmpClient *c) {
        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return 0;

        c->state = QMP_CLIENT_DISCONNECTED;

        /* Disable event sources so we don't busy-loop on the EOF condition.
         * Matches sd_varlink_close()'s varlink_detach_event_sources(). */
        if (c->io_event_source)
                (void) sd_event_source_set_enabled(c->io_event_source, SD_EVENT_OFF);
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_OFF);

        qmp_client_fail_pending(c, -ECONNRESET);
        qmp_client_emit_synthetic_shutdown(c);
        if (c->disconnect_callback)
                c->disconnect_callback(c, c->userdata);

        return 1;
}

static void qmp_client_clear(QmpClient *c) {
        assert(c);

        qmp_client_handle_disconnect(c);
        qmp_client_detach_event(c);
        c->fd = safe_close(c->fd);

        close_many(c->pushed_fds, c->n_pushed_fds);
        c->pushed_fds = mfree(c->pushed_fds);
        c->n_pushed_fds = 0;

        while (c->output_queue) {
                QmpOutputItem *item = c->output_queue;
                LIST_REMOVE(queue, c->output_queue, item);
                qmp_output_item_free(item);
        }
        c->output_queue_tail = NULL;
        c->n_output_queue = 0;

        free(c->output_buffer);
        c->output_buffer = NULL;
        c->output_buffer_index = c->output_buffer_size = 0;

        close_many(c->output_fds, c->n_output_fds);
        c->output_fds = mfree(c->output_fds);
        c->n_output_fds = 0;
}

/* Drain all pending output. Blocks until the output buffer is empty, matching
 * sd_varlink_flush(). */
int qmp_client_flush(QmpClient *c) {
        int r;

        if (!c)
                return 0;

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;

        for (;;) {
                if (c->output_buffer_size == 0 && !c->output_queue)
                        break;
                if (c->write_disconnected)
                        return -ECONNRESET;

                r = qmp_client_write(c);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = fd_wait_for_event(c->fd, POLLOUT, USEC_INFINITY);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Close the QMP connection: notify pending callbacks, fire disconnect callback,
 * detach event sources, close the fd. The object stays alive until the last
 * unref. Matches sd_varlink_close(). */
int qmp_client_close(QmpClient *c) {
        if (!c)
                return 0;

        /* Take a temporary ref to prevent destruction mid-callback,
         * matching sd_varlink_close()'s pattern. */
        qmp_client_ref(c);
        qmp_client_clear(c);
        qmp_client_unref(c);

        return 1;
}

QmpClient* qmp_client_close_unref(QmpClient *c) {
        qmp_client_close(c);
        return qmp_client_unref(c);
}

QmpClient* qmp_client_flush_close_unref(QmpClient *c) {
        if (!c)
                return NULL;

        (void) qmp_client_flush(c);
        return qmp_client_close_unref(c);
}

/* Handle handshake progression through sub-states:
 * HANDSHAKE_INITIAL → receive greeting → HANDSHAKE_GREETING_RECEIVED
 * HANDSHAKE_GREETING_RECEIVED → send qmp_capabilities → HANDSHAKE_CAPABILITIES_SENT
 * HANDSHAKE_CAPABILITIES_SENT → receive response → IDLE */
static int qmp_client_dispatch_handshake(QmpClient *c) {
        int r;

        assert(c);
        assert(QMP_CLIENT_STATE_IS_HANDSHAKE(c->state));

        if (!c->current)
                return 0;

        switch (c->state) {

        case QMP_CLIENT_HANDSHAKE_INITIAL:
                /* Waiting for QMP greeting */
                if (!sd_json_variant_by_key(c->current, "QMP")) {
                        log_debug("Expected QMP greeting, got something else");
                        qmp_client_clear_current(c);
                        return -EPROTO;
                }

                qmp_client_clear_current(c);
                c->state = QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED;

                /* Fall through to immediately send capabilities */
                _fallthrough_;

        case QMP_CLIENT_HANDSHAKE_GREETING_RECEIVED: {
                /* Send qmp_capabilities command */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
                r = sd_json_buildo(
                                &cmd,
                                SD_JSON_BUILD_PAIR_STRING("execute", "qmp_capabilities"),
                                SD_JSON_BUILD_PAIR_UNSIGNED("id", c->next_id++));
                if (r < 0)
                        return r;

                r = qmp_client_enqueue(c, cmd);
                if (r < 0)
                        return r;

                c->state = QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT;
                return 1;
        }

        case QMP_CLIENT_HANDSHAKE_CAPABILITIES_SENT: {
                /* Waiting for qmp_capabilities response */
                sd_json_variant *error = sd_json_variant_by_key(c->current, "error");
                if (error) {
                        _cleanup_free_ char *desc = qmp_extract_error_description(error);
                        log_debug("qmp_capabilities failed: %s", strnull(desc));
                        qmp_client_clear_current(c);
                        return -EPROTO;
                }

                qmp_client_clear_current(c);
                c->state = QMP_CLIENT_IDLE;
                return 1;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

static int qmp_client_dispatch(QmpClient *c) {
        assert(c);

        if (!c->current)
                return 0;

        if (QMP_CLIENT_STATE_IS_HANDSHAKE(c->state))
                return qmp_client_dispatch_handshake(c);

        return qmp_client_dispatch_reply(c);
}

/* Perform a single step of QMP processing. Returns 1 if progress was made, 0 if nothing
 * is available (caller should wait), negative on error. Matches sd-varlink's
 * sd_varlink_process() pattern. Step chain: write → dispatch → parse → read → disconnect.
 * When attached to an event loop, enables the defer event source on progress so
 * processing continues on the next event loop iteration. */
int qmp_client_process(QmpClient *c) {
        int r;

        assert(c);

        if (c->state == QMP_CLIENT_DISCONNECTED || c->state == _QMP_CLIENT_STATE_INVALID)
                return -ENOTCONN;

        /* Take a temporary ref to prevent destruction mid-callback, matching
         * sd_varlink_process()'s pattern. A callback invoked during dispatch might
         * drop the last external ref, which would otherwise free us mid-execution. */
        qmp_client_ref(c);

        /* 1. Write — drain output buffer */
        r = qmp_client_write(c);
        if (r != 0)
                goto finish;

        /* 2. Dispatch — route based on state */
        r = qmp_client_dispatch(c);
        if (r != 0)
                goto finish;

        /* 3. Parse — extract one complete message into c->current */
        r = qmp_client_parse_message(c, &c->current);
        if (r != 0)
                goto finish;

        /* 4. Read — fill input buffer from fd */
        r = qmp_client_read(c);
        if (r == -EAGAIN) {
                r = 0; /* Nothing available, caller should wait */
                goto finish;
        }
        if (r < 0) {
                if (ERRNO_IS_DISCONNECT(r))
                        qmp_client_handle_disconnect(c);
                else
                        log_debug_errno(r, "Failed to fill QMP buffer: %m");
                goto finish;
        }

finish:
        /* If progress was made and we have a defer source, enable it so we get called again
         * on the next event loop iteration — matching sd-varlink's pattern. */
        if (r >= 0 && c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);

        if (r < 0 && c->state != QMP_CLIENT_DISCONNECTED)
                /* On error, initiate disconnection — matching sd_varlink_process()'s
                 * transition to VARLINK_PENDING_DISCONNECT on failure. */
                qmp_client_handle_disconnect(c);

        qmp_client_update_events(c);
        qmp_client_unref(c);
        return r;
}

static int qmp_client_defer_callback(sd_event_source *source, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        (void) qmp_client_process(c);

        return 1;
}

static int qmp_client_io_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);

        (void) qmp_client_process(c);

        return 1;
}

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. The fd is switched
 * to non-blocking immediately. The handshake (greeting + qmp_capabilities) runs through
 * the process()+wait() loop using the HANDSHAKING state. Call qmp_client_attach_event()
 * afterwards for async operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd) {
        _cleanup_(qmp_client_unrefp) QmpClient *c = NULL;
        int r;

        assert(ret);
        assert(fd >= 0);

        c = new(QmpClient, 1);
        if (!c)
                return -ENOMEM;

        *c = (QmpClient) {
                .n_ref = 1,
                .fd = TAKE_FD(fd),
                .state = QMP_CLIENT_HANDSHAKE_INITIAL,
                .next_id = 1,
        };

        r = fd_nonblock(c->fd, true);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority) {
        int r;

        assert(c);
        assert(event);
        assert(!c->event);

        c->event = sd_event_ref(event);

        r = sd_event_add_io(c->event, &c->io_event_source, c->fd, EPOLLIN, qmp_client_io_callback, c);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(c->io_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(c->io_event_source, c->description ?: "qmp-client-io");

        r = sd_event_add_defer(c->event, &c->defer_event_source, qmp_client_defer_callback, c);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(c->defer_event_source, priority);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_OFF);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(c->defer_event_source, c->description ?: "qmp-client-defer");

        return 0;

fail:
        qmp_client_detach_event(c);
        return r;
}

void qmp_client_detach_event(QmpClient *c) {
        if (!c)
                return;

        c->defer_event_source = sd_event_source_disable_unref(c->defer_event_source);
        c->io_event_source = sd_event_source_disable_unref(c->io_event_source);
        c->event = sd_event_unref(c->event);
}

int qmp_client_invoke(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_free_ QmpPendingCommand *pending = NULL;
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(callback);

        if (c->state == QMP_CLIENT_DISCONNECTED)
                return -ENOTCONN;
        if (c->state != QMP_CLIENT_IDLE)
                return -EBUSY;

        r = qmp_client_build_command(c, command, arguments, &cmd, &id);
        if (r < 0)
                return r;

        pending = new(QmpPendingCommand, 1);
        if (!pending)
                return -ENOMEM;

        *pending = (QmpPendingCommand) {
                .id       = id,
                .callback = callback,
                .userdata = userdata,
        };

        r = hashmap_ensure_put(&c->pending_commands, &qmp_pending_command_hash_ops, pending, pending);
        if (r < 0)
                return r;

        r = qmp_client_enqueue(c, cmd);
        if (r < 0) {
                hashmap_remove(c->pending_commands, pending);
                return r;
        }

        /* Enable defer source so process() runs on next event loop iteration to
         * drain the output buffer. Update io events for EPOLLOUT. */
        if (c->defer_event_source)
                (void) sd_event_source_set_enabled(c->defer_event_source, SD_EVENT_ON);
        qmp_client_update_events(c);

        TAKE_PTR(pending);
        return 0;
}

int qmp_client_push_fd(QmpClient *c, int fd) {
        assert(c);
        assert(fd >= 0);

        if (c->n_pushed_fds >= SCM_MAX_FD) /* Kernel limit of 253 fds per SCM_RIGHTS message */
                return -ENOBUFS;

        if (!GREEDY_REALLOC(c->pushed_fds, c->n_pushed_fds + 1))
                return -ENOMEM;

        int i = (int) c->n_pushed_fds;
        c->pushed_fds[c->n_pushed_fds++] = fd;
        return i;
}

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback) {
        assert(c);
        c->event_callback = callback;
}

void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback) {
        assert(c);
        c->disconnect_callback = callback;
}

void *qmp_client_set_userdata(QmpClient *c, void *userdata) {
        void *old;

        assert(c);

        old = c->userdata;
        c->userdata = userdata;
        return old;
}

void *qmp_client_get_userdata(QmpClient *c) {
        assert(c);
        return c->userdata;
}

int qmp_client_set_description(QmpClient *c, const char *description) {
        assert(c);
        return free_and_strdup(&c->description, description);
}

sd_event *qmp_client_get_event(QmpClient *c) {
        return c ? c->event : NULL;
}

bool qmp_client_is_handshaking(QmpClient *c) {
        return c && QMP_CLIENT_STATE_IS_HANDSHAKE(c->state);
}


unsigned qmp_client_next_fdset_id(QmpClient *c) {
        assert(c);
        return c->next_fdset_id++;
}

static QmpClient* qmp_client_destroy(QmpClient *c) {
        if (!c)
                return NULL;

        qmp_client_clear(c);

        sd_json_variant_unref(c->current);
        free(c->input_buffer);
        free(c->description);
        hashmap_free(c->pending_commands);

        return mfree(c);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(QmpClient, qmp_client, qmp_client_destroy);
