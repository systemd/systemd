/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "qmp-client.h"
#include "string-util.h"
#include "time-util.h"

#define QMP_READ_SIZE 4096
#define QMP_BUFFER_MAX (16U * 1024U * 1024U)

struct QmpClient {
        int fd;
        sd_event *event;
        sd_event_source *io_event_source;

        char *input_buffer;            /* valid data at input_buffer+input_buffer_index, length input_buffer_size */
        size_t input_buffer_index;
        size_t input_buffer_size;
        size_t input_buffer_unscanned; /* bytes not yet scanned for \n delimiter */

        uint64_t next_id;

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

/* Try to extract a complete \n-delimited line from the buffer. Only scans the unscanned portion to avoid
 * redundant work on large buffers. Returns 1 + line in *ret if found, 0 if incomplete, negative on error. */
static int qmp_client_extract_line(QmpClient *c, char **ret) {
        char *begin, *newline;
        size_t sz;

        assert(c);
        assert(ret);

        if (c->input_buffer_unscanned <= 0)
                return 0;

        assert(c->input_buffer_unscanned <= c->input_buffer_size);

        begin = c->input_buffer + c->input_buffer_index;

        newline = memchr(begin + c->input_buffer_size - c->input_buffer_unscanned,
                         '\n', c->input_buffer_unscanned);
        if (!newline) {
                c->input_buffer_unscanned = 0;
                return 0;
        }

        sz = newline - begin + 1;

        _cleanup_free_ char *line = strndup(begin, newline - begin);
        if (!line)
                return -ENOMEM;

        /* QMP terminates with \r\n (QEMU's monitor_puts converts \n to \r\n). Strip the trailing \r. */
        delete_trailing_chars(line, "\r");

        c->input_buffer_size -= sz;
        if (c->input_buffer_size == 0)
                c->input_buffer_index = 0;
        else
                c->input_buffer_index += sz;
        c->input_buffer_unscanned = c->input_buffer_size;

        *ret = TAKE_PTR(line);
        return 1;
}

/* Read from the fd until a complete line is available. Handles both blocking (Phase 1) and non-blocking (Phase
 * 2) modes: in blocking mode read() blocks naturally; in non-blocking mode we use fd_wait_for_event() to poll.
 * Returns 1 + line in *ret on success, negative on error. */
static int qmp_client_read_line(QmpClient *c, char **ret) {
        int r;

        assert(c);
        assert(ret);

        for (;;) {
                r = qmp_client_extract_line(c, ret);
                if (r != 0)
                        return r;

                r = qmp_client_fill_buffer(c);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Non-blocking mode, no data available yet. Wait for data. On a local
                         * socketpair we'll always get a response or a hangup, no timeout needed. */
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

        if (!ret)
                return 0;

        class = sd_json_variant_by_key(error, "class");
        if (!class)
                return 0;

        return free_and_strdup(ret, sd_json_variant_string(class));
}

static bool qmp_response_matches_id(sd_json_variant *response, uint64_t id) {
        sd_json_variant *resp_id;

        resp_id = sd_json_variant_by_key(response, "id");
        return resp_id && sd_json_variant_unsigned(resp_id) == id;
}

/* Send a QMP command and wait for the matching response. Events arriving in the meantime are dispatched
 * to the event callback. Returns 0 on success, -EIO on QMP error (with error class in ret_error if
 * provided), negative errno on transport failure. */
static int qmp_client_call(QmpClient *c, const char *command, sd_json_variant *arguments,
                           sd_json_variant **ret_result, char **ret_error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        uint64_t id;
        int r;

        assert(c);
        assert(command);

        id = c->next_id++;

        r = sd_json_buildo(
                        &cmd,
                        SD_JSON_BUILD_PAIR_STRING("execute", command),
                        SD_JSON_BUILD_PAIR_CONDITION(!!arguments, "arguments", SD_JSON_BUILD_VARIANT(arguments)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", id));
        if (r < 0)
                return r;

        r = qmp_client_write_json(c, cmd);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *response = NULL;
                sd_json_variant *result, *error;

                r = qmp_client_read_line(c, &line);
                if (r < 0)
                        return r;

                r = sd_json_parse(line, 0, &response, NULL, NULL);
                if (r < 0)
                        return r;

                if (sd_json_variant_by_key(response, "event")) {
                        qmp_client_dispatch_event(c, response);
                        continue;
                }

                if (!qmp_response_matches_id(response, id)) {
                        log_debug("Discarding unmatched QMP response");
                        continue;
                }

                result = sd_json_variant_by_key(response, "return");
                if (result) {
                        if (ret_result)
                                *ret_result = sd_json_variant_ref(result);
                        return 0;
                }

                error = sd_json_variant_by_key(response, "error");
                if (error) {
                        r = qmp_extract_error_class(error, ret_error);
                        if (r < 0)
                                return r;
                        return -EIO;
                }

                return -EPROTO;
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
        qmp_client_emit_synthetic_shutdown(c);
        if (c->disconnect_callback)
                c->disconnect_callback(c, c->disconnect_userdata);
}

static int qmp_client_io_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        QmpClient *c = ASSERT_PTR(userdata);
        int r;

        /* Read all available data */
        for (;;) {
                r = qmp_client_fill_buffer(c);
                if (r == 0)
                        break;
                if (r < 0) {
                        if (ERRNO_IS_NEG_DISCONNECT(r))
                                qmp_client_handle_disconnect(c);
                        return 0;
                }
        }

        /* Process all complete messages */
        for (;;) {
                _cleanup_free_ char *line = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = qmp_client_extract_line(c, &line);
                if (r <= 0)
                        break;

                r = sd_json_parse(line, 0, &v, NULL, NULL);
                if (r < 0) {
                        log_warning_errno(r, "Failed to parse QMP message, disconnecting: %m");
                        qmp_client_handle_disconnect(c);
                        return 0;
                }

                qmp_client_dispatch_event(c, v);
        }

        /* Handle hangup after draining data */
        if (revents & (EPOLLHUP|EPOLLERR))
                qmp_client_handle_disconnect(c);

        return 0;
}

static int qmp_client_read_greeting(QmpClient *c) {
        _cleanup_free_ char *line = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *greeting = NULL;
        int r;

        assert(c);

        r = qmp_client_read_line(c, &line);
        if (r < 0)
                return r;

        r = sd_json_parse(line, 0, &greeting, NULL, NULL);
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

        r = qmp_client_call(c, "qmp_capabilities", NULL, NULL, NULL);
        if (r < 0)
                return r;

        /* Phase 2: Switch to async mode. Set the fd to non-blocking and attach an I/O event source to
         * the caller's event loop (vmspawn's sd-event loop) for processing async QMP events (STOP, RESUME,
         * SHUTDOWN, etc.) that arrive on the socketpair between blocking qmp_client_execute() calls.
         * Leftover bytes in the read buffer are preserved. */
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
                sd_json_variant **ret_result,
                char **ret_error) {

        int r;

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);

        if (!c->connected)
                return -ENOTCONN;

        /* Disable the async IO event source while we do synchronous request-response exchange, to avoid
         * interference between the event loop callback and our blocking read.
         *
         * TODO: This blocks the event loop. Acceptable for the fast commands we issue today (stop, cont,
         * query-status), but should be converted to async dispatch with a pending-request hashmap for
         * general use. */
        assert(c->io_event_source);

        r = sd_event_source_set_enabled(c->io_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        r = qmp_client_call(c, command, arguments, ret_result, ret_error);

        /* For errors that aren't clearly a disconnect or a clean QMP error response,
         * ping QEMU to check if it's still alive. Upgrades to -ENOTCONN if QEMU is dead. */
        if (r < 0 && r != -EIO && !ERRNO_IS_NEG_DISCONNECT(r))
                if (qmp_client_call(c, "query-version", NULL, NULL, NULL) < 0)
                        r = -ENOTCONN;

        if (ERRNO_IS_NEG_DISCONNECT(r))
                qmp_client_handle_disconnect(c);
        else
                (void) sd_event_source_set_enabled(c->io_event_source, SD_EVENT_ON);

        return r;
}

int qmp_client_get_schema(QmpClient *c, sd_json_variant **ret_schema) {
        assert_return(c, -EINVAL);
        assert_return(ret_schema, -EINVAL);

        return qmp_client_execute(c, "query-qmp-schema", NULL, ret_schema, NULL);
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
        if (!c)
                return NULL;

        c->io_event_source = sd_event_source_disable_unref(c->io_event_source);
        c->event = sd_event_unref(c->event);
        c->fd = safe_close(c->fd);
        free(c->input_buffer);

        return mfree(c);
}
