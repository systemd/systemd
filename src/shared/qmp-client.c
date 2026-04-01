/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"
#include "time-util.h"

#define QMP_READ_SIZE ((size_t) 4096)
#define QMP_BUFFER_MAX (16U * 1024U * 1024U)

typedef struct QmpPendingCommand {
        qmp_command_callback_t callback;
        void *userdata;
} QmpPendingCommand;

struct QmpClient {
        int fd;
        sd_event *event;
        sd_event_source *io_event_source;

        char *input_buffer;            /* valid data at input_buffer+input_buffer_index, length input_buffer_size */
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned; /* bytes not yet scanned for \n delimiter */

        uint64_t next_id;
        Hashmap *pending_commands;     /* id → QmpPendingCommand*, for async dispatch */

        qmp_event_callback_t event_callback;
        void *event_userdata;
        qmp_disconnect_callback_t disconnect_callback;
        void *disconnect_userdata;

        bool connected;
};

/* Try to read available data from the fd into the buffer. Returns 1 if data was read, 0 if EAGAIN, negative on
 * error. Returns -ECONNRESET on EOF. Uses the varlink-style index+size buffer pattern to avoid memmove(). */
static int qmp_client_fill_buffer(QmpClient *c) {
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
        if (n < 0)
                n = -errno;
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        if (n < 0)
                return n;
        if (n == 0)
                return -ECONNRESET;

        c->input_buffer_size += n;
        c->input_buffer_unscanned += n;
        return 1;
}

/* Try to parse one complete QMP message from the buffer. QMP uses \n as the message delimiter (QEMU's
 * monitor_puts converts \n to \r\n on the wire, but \r is JSON whitespace and handled transparently by
 * sd_json_parse). We NUL-terminate the buffer at the \n position so sd_json_parse() can work directly on it
 * without copying — the same pattern varlink uses for its \0-delimited messages. Returns 1 + parsed value in
 * *ret if a complete message was found, 0 if no complete message is available yet, negative on parse error. */
static int qmp_client_parse_message(QmpClient *c, sd_json_variant **ret) {
        char *begin, *e;
        size_t sz;
        int r;

        assert(c);
        assert(ret);

        if (c->input_buffer_unscanned == 0)
                return 0;

        assert(c->input_buffer_unscanned <= c->input_buffer_size);

        begin = c->input_buffer + c->input_buffer_index;

        e = memchr(begin + c->input_buffer_size - c->input_buffer_unscanned, '\n', c->input_buffer_unscanned);
        if (!e) {
                c->input_buffer_unscanned = 0;
                return 0;
        }

        sz = e - begin + 1;

        *e = '\0';

        r = sd_json_parse(begin, 0, ret, NULL, NULL);
        if (r < 0) {
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

/* Read from the fd until a complete QMP message is available and parsed. Handles both blocking and non-blocking
 * fds: in blocking mode read() blocks naturally; in non-blocking mode we poll with fd_wait_for_event(). */
static int qmp_client_read_message(QmpClient *c, sd_json_variant **ret) {
        int r;

        assert(c);
        assert(ret);

        for (;;) {
                r = qmp_client_parse_message(c, ret);
                if (r != 0)
                        return r;

                r = qmp_client_fill_buffer(c);
                if (r < 0)
                        return r;
                if (r == 0) {
                        r = fd_wait_for_event(c->fd, POLLIN, USEC_INFINITY);
                        if (r < 0)
                                return r;
                }
        }
}

static int qmp_client_write_json(QmpClient *c, sd_json_variant *v) {
        _cleanup_free_ char *json_str = NULL;
        int r;

        assert(c);
        assert(v);

        r = sd_json_variant_format(v, 0, &json_str);
        if (r < 0)
                return r;

        if (!strextend(&json_str, "\n"))
                return -ENOMEM;

        return loop_write(c->fd, json_str, SIZE_MAX);
}

static void qmp_client_dispatch_event(QmpClient *c, sd_json_variant *v) {
        sd_json_variant *event_name, *data, *timestamp;
        uint64_t ts_s = 0, ts_us = 0;

        assert(c);
        assert(v);

        event_name = sd_json_variant_by_key(v, "event");
        if (!event_name || !sd_json_variant_is_string(event_name))
                return;
        if (!c->event_callback)
                return;

        data = sd_json_variant_by_key(v, "data");
        timestamp = sd_json_variant_by_key(v, "timestamp");
        if (timestamp) {
                ts_s = sd_json_variant_unsigned(sd_json_variant_by_key(timestamp, "seconds"));
                ts_us = sd_json_variant_unsigned(sd_json_variant_by_key(timestamp, "microseconds"));
        }

        c->event_callback(c, sd_json_variant_string(event_name), data, ts_s, ts_us, c->event_userdata);
}

static int qmp_extract_error_class(sd_json_variant *error, char **ret) {
        sd_json_variant *class;

        assert(ret);

        class = sd_json_variant_by_key(error, "class");
        if (!class)
                return 0;

        return free_and_strdup(ret, sd_json_variant_string(class));
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

/* Send a QMP command and wait for the matching response. Events arriving in the meantime are dispatched
 * to the event callback. Returns 0 on success, -EIO on QMP error, negative errno on transport failure. */
static int qmp_client_call(QmpClient *c, const char *command, sd_json_variant *arguments) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        uint64_t id;
        int r;

        assert(c);
        assert(command);

        r = qmp_client_build_command(c, command, arguments, &cmd, &id);
        if (r < 0)
                return r;

        r = qmp_client_write_json(c, cmd);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;
                sd_json_variant *resp_id;

                r = qmp_client_read_message(c, &response);
                if (r < 0)
                        return r;

                if (sd_json_variant_by_key(response, "event")) {
                        qmp_client_dispatch_event(c, response);
                        continue;
                }

                resp_id = sd_json_variant_by_key(response, "id");
                if (!resp_id || sd_json_variant_unsigned(resp_id) != id) {
                        log_debug("Discarding unmatched QMP response");
                        continue;
                }

                if (sd_json_variant_by_key(response, "return"))
                        return 0;

                if (sd_json_variant_by_key(response, "error"))
                        return -EIO;

                return -EPROTO;
        }
}

/* Dispatch a parsed QMP message: route command responses to pending async callbacks,
 * and events to the event callback. */
static void qmp_client_dispatch_message(QmpClient *c, sd_json_variant *v) {
        sd_json_variant *id_variant, *result, *error;

        assert(c);
        assert(v);

        /* Events have an "event" key */
        if (sd_json_variant_by_key(v, "event")) {
                qmp_client_dispatch_event(c, v);
                return;
        }

        /* Command responses have an "id" key — match against pending async commands */
        id_variant = sd_json_variant_by_key(v, "id");
        if (id_variant) {
                uint64_t id = sd_json_variant_unsigned(id_variant);
                _cleanup_free_ QmpPendingCommand *pending = hashmap_remove(c->pending_commands, UINT64_TO_PTR(id));
                if (!pending) {
                        log_debug("Discarding unmatched QMP response for id %" PRIu64, id);
                        return;
                }

                result = sd_json_variant_by_key(v, "return");
                if (result) {
                        pending->callback(c, result, NULL, 0, pending->userdata);
                        return;
                }

                error = sd_json_variant_by_key(v, "error");
                if (error) {
                        _cleanup_free_ char *error_class = NULL;
                        (void) qmp_extract_error_class(error, &error_class);
                        pending->callback(c, NULL, error_class, -EIO, pending->userdata);
                        return;
                }

                pending->callback(c, NULL, NULL, -EPROTO, pending->userdata);
                return;
        }

        log_debug("Discarding unrecognized QMP message");
}

/* Fail all pending async commands with the given error. Called on disconnect. */
static void qmp_client_fail_pending(QmpClient *c, int error) {
        QmpPendingCommand *p;

        assert(c);

        while ((p = hashmap_steal_first(c->pending_commands))) {
                p->callback(c, NULL, NULL, error, p->userdata);
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

        c->event_callback(c, "SHUTDOWN", data, 0, 0, c->event_userdata);
}

static void qmp_client_handle_disconnect(QmpClient *c) {
        assert(c);

        if (!c->connected)
                return;

        c->connected = false;
        if (c->io_event_source)
                (void) sd_event_source_set_enabled(c->io_event_source, SD_EVENT_OFF);
        qmp_client_fail_pending(c, -ECONNRESET);
        qmp_client_emit_synthetic_shutdown(c);
        if (c->disconnect_callback)
                c->disconnect_callback(c, c->disconnect_userdata);
}

static int qmp_client_io_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);
        bool got_eof = false;
        int r;

        /* Read all available data */
        for (;;) {
                r = qmp_client_fill_buffer(c);
                if (r == 0)
                        break;
                if (r < 0) {
                        got_eof = true;
                        break; /* Drain buffered messages below before handling disconnect */
                }
        }

        /* Parse all complete messages in the buffer. This must happen before disconnect handling
         * so that a final command response arriving together with EOF is properly dispatched. */
        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = qmp_client_parse_message(c, &v);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse QMP message, disconnecting: %m");
                        qmp_client_handle_disconnect(c);
                        return 0;
                }
                if (r == 0)
                        break;

                qmp_client_dispatch_message(c, v);
        }

        /* Handle disconnect after draining all buffered data */
        if (got_eof || (revents & (EPOLLHUP|EPOLLERR)))
                qmp_client_handle_disconnect(c);

        return 0;
}

static int qmp_client_read_greeting(QmpClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *greeting = NULL;
        int r;

        assert(c);

        r = qmp_client_read_message(c, &greeting);
        if (r < 0)
                return r;

        if (!sd_json_variant_by_key(greeting, "QMP"))
                return -EPROTO;

        return 0;
}

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd (closes it on error or when
 * the QmpClient is freed). Performs a blocking handshake: reads greeting, sends qmp_capabilities, waits
 * for success. Then switches fd to non-blocking and attaches to sd_event for async event processing. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event) {
        _cleanup_(qmp_client_freep) QmpClient *c = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);

        c = new(QmpClient, 1);
        if (!c)
                return -ENOMEM;

        *c = (QmpClient) {
                .fd = TAKE_FD(fd),
                .event = sd_event_ref(event),
                .connected = true,
                .next_id = 1,
        };

        /* Phase 1: Blocking handshake. The fd is in blocking mode at this point. Read the QMP greeting,
         * then send qmp_capabilities via qmp_client_call() which handles the response loop. If QEMU dies
         * during this, read() returns 0 (EOF). */
        r = qmp_client_read_greeting(c);
        if (r < 0)
                return r;

        r = qmp_client_call(c, "qmp_capabilities", NULL);
        if (r < 0)
                return r;

        /* Phase 2: Switch to async mode. Set the fd to non-blocking and attach an I/O event source to
         * the caller's event loop for processing QMP responses and async events (STOP, RESUME, SHUTDOWN,
         * etc.) arriving on the socketpair. Leftover bytes in the read buffer are preserved. */
        r = fd_nonblock(c->fd, true);
        if (r < 0)
                return r;

        r = sd_event_add_io(c->event, &c->io_event_source, c->fd, EPOLLIN, qmp_client_io_callback, c);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(c->io_event_source, "qmp-client-io");

        *ret = TAKE_PTR(c);
        return 0;
}

int qmp_client_execute(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_free_ QmpPendingCommand *pending = NULL;
        uint64_t id;
        int r;

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);
        assert_return(callback, -EINVAL);

        if (!c->connected)
                return -ENOTCONN;

        r = qmp_client_build_command(c, command, arguments, &cmd, &id);
        if (r < 0)
                return r;

        pending = new(QmpPendingCommand, 1);
        if (!pending)
                return -ENOMEM;

        *pending = (QmpPendingCommand) {
                .callback = callback,
                .userdata = userdata,
        };

        r = hashmap_ensure_put(&c->pending_commands, &trivial_hash_ops, UINT64_TO_PTR(id), pending);
        if (r < 0)
                return r;

        r = qmp_client_write_json(c, cmd);
        if (r < 0) {
                hashmap_remove(c->pending_commands, UINT64_TO_PTR(id));
                return r;
        }

        TAKE_PTR(pending);
        return 0;
}

void qmp_client_set_event_callback(QmpClient *c, qmp_event_callback_t callback, void *userdata) {
        assert(c);

        c->event_callback = callback;
        c->event_userdata = userdata;
}

void qmp_client_set_disconnect_callback(QmpClient *c, qmp_disconnect_callback_t callback, void *userdata) {
        assert(c);

        c->disconnect_callback = callback;
        c->disconnect_userdata = userdata;
}

QmpClient *qmp_client_free(QmpClient *c) {
        QmpPendingCommand *p;

        if (!c)
                return NULL;

        c->io_event_source = sd_event_source_disable_unref(c->io_event_source);
        c->event = sd_event_unref(c->event);
        c->fd = safe_close(c->fd);
        free(c->input_buffer);

        /* Any remaining pending commands are orphaned (disconnect should have drained them) */
        while ((p = hashmap_steal_first(c->pending_commands)))
                free(p);
        hashmap_free(c->pending_commands);

        return mfree(c);
}
