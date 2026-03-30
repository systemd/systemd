/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "log.h"
#include "qmp-client.h"
#include "socket-util.h"
#include "string-util.h"

/* Match QEMU's own CHR_READ_BUF_LEN (include/chardev/char.h) for the per-read() chunk size.
 * Normal QMP responses are well under 4K; the largest message (query-qmp-schema, ~230K) is
 * only read once during the blocking handshake at startup, so the extra syscalls are negligible. */
#define QMP_READ_SIZE ((size_t) 4096)

/* Match VARLINK_BUFFER_MAX from sd-varlink.c — same defensive upper bound on accumulated input. */
#define QMP_BUFFER_MAX (16U * 1024U * 1024U)

typedef struct QmpPendingCommand {
        qmp_command_callback_t callback;
        void *userdata;
} QmpPendingCommand;

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

        unsigned next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

        bool connected;
        QmpClientFeature features;
};

static int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority);
static void qmp_client_detach_event(QmpClient *c);

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

/* Read from the non-blocking fd until a complete QMP message is available and parsed. Uses
 * process+wait in a tight loop — the caller drives processing directly, matching how
 * sd-varlink's varlink_call_internal() uses sd_varlink_process() + sd_varlink_wait(). */
static int qmp_client_read_message(QmpClient *c, sd_json_variant **ret) {
        int r;

        assert(c);
        assert(ret);

        for (;;) {
                r = qmp_client_parse_message(c, ret);
                if (r != 0)
                        return r;

                r = qmp_client_fill_buffer(c);
                if (r == -EAGAIN) {
                        r = fd_wait_for_event(c->fd, POLLIN, USEC_INFINITY);
                        if (ERRNO_IS_NEG_TRANSIENT(r))
                                continue;
                        if (r < 0)
                                return r;
                        continue;
                }
                if (r < 0)
                        return r;
        }
}

static int qmp_client_write_json_fd(QmpClient *c, sd_json_variant *v, int fd) {
        _cleanup_free_ char *json_str = NULL;
        int r;

        assert(c);
        assert(v);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_NEWLINE, &json_str);
        if (r < 0)
                return r;

        if (fd >= 0) {
                /* Send the JSON message with an FD as SCM_RIGHTS ancillary data in a single
                 * sendmsg() call. QEMU's getfd command requires the FD to arrive as ancillary
                 * data alongside the command JSON. */
                struct iovec iov = IOVEC_MAKE_STRING(json_str);
                ssize_t n = send_one_fd_iov_sa(c->fd, fd, &iov, 1, /* sa= */ NULL, /* len= */ 0, /* flags= */ 0);
                if (n < 0)
                        return (int) n;
                return 0;
        }

        /* The fd is non-blocking, so loop_write() could return -EAGAIN if the socket buffer is
         * full. In practice QMP commands are tiny (< 1KB) and the kernel socket buffer is 128KB+,
         * so this cannot happen in any realistic scenario. */
        return loop_write(c->fd, json_str, SIZE_MAX);
}

static int qmp_client_write_json(QmpClient *c, sd_json_variant *v) {
        return qmp_client_write_json_fd(c, v, -EBADF);
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
                { "event", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  offsetof(typeof(p), event), SD_JSON_MANDATORY },
                { "data",  SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, offsetof(typeof(p), data),  0                 },
                {},
        };

        if (sd_json_dispatch(v, table, SD_JSON_ALLOW_EXTENSIONS, &p) < 0)
                return 0;

        r = c->event_callback(c, p.event, p.data, c->userdata);
        if (r < 0)
                log_debug_errno(r, "Event callback returned error, ignoring: %m");

        return 1;
}

static char *qmp_extract_error_description(sd_json_variant *error) {
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
 * Matches sd_varlink_call(): if ret_error_desc is NULL and a QMP error occurs, returns
 * -EIO. If ret_error_desc is provided, returns 0 and sets it to the error description
 * (caller-owned, must free). On success, returns 0 with ret_result (if requested). */
static int qmp_client_call(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                char **ret_error_desc) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL, *response = NULL;
        int r;

        assert(c);
        assert(command);

        r = qmp_client_build_command(c, command, arguments, &cmd, /* ret_id= */ NULL);
        if (r < 0)
                return r;

        r = qmp_client_write_json(c, cmd);
        if (r < 0)
                return r;

        r = qmp_client_read_message(c, &response);
        if (r < 0)
                return r;

        sd_json_variant *result = sd_json_variant_by_key(response, "return");
        if (result) {
                if (ret_result)
                        *ret_result = sd_json_variant_ref(result);
                if (ret_error_desc)
                        *ret_error_desc = NULL;
                return 0;
        }

        sd_json_variant *error = sd_json_variant_by_key(response, "error");
        if (error) {
                if (!ret_error_desc)
                        return -EIO;

                *ret_error_desc = qmp_extract_error_description(error);
                return 0;
        }

        return -EPROTO;
}

/* Probe whether QEMU supports aio=io_uring by attempting a dummy blockdev-add. */
static int qmp_client_probe_io_uring(QmpClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_desc = NULL;
        int r;

        assert(c);

        r = sd_json_buildo(
                        &args,
                        SD_JSON_BUILD_PAIR_STRING("node-name", "__io_uring_probe"),
                        SD_JSON_BUILD_PAIR_STRING("driver", "file"),
                        SD_JSON_BUILD_PAIR_STRING("filename", "/dev/null"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("read-only", true),
                        SD_JSON_BUILD_PAIR_STRING("aio", "io_uring"));
        if (r < 0)
                return r;

        r = qmp_client_call(c, "blockdev-add", args, /* ret_result= */ NULL, &error_desc);
        if (r < 0)
                return r;
        if (error_desc) {
                log_debug("QEMU does not support aio=io_uring: %s", error_desc);
                return 0;
        }

        c->features |= QMP_CLIENT_FEATURE_IO_URING;

        /* Clean up the probe node */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *del_args = NULL;
        r = sd_json_buildo(&del_args,
                        SD_JSON_BUILD_PAIR_STRING("node-name", "__io_uring_probe"));
        if (r < 0)
                return r;

        r = qmp_client_call(c, "blockdev-del", del_args, /* ret_result= */ NULL, /* ret_error_desc= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to remove io_uring probe node: %m");

        log_debug("QEMU supports aio=io_uring");
        return 0;
}

/* Dispatch a parsed QMP message: route command responses to pending async callbacks,
 * and events to the event callback. Returns 1 on successful dispatch to signal "work
 * was done" to the process() loop — matching sd-varlink's dispatch pattern. Callback
 * errors are logged but not propagated (same as sd-varlink's reply dispatch). */
static int qmp_client_dispatch_message(QmpClient *c, sd_json_variant *v) {
        sd_json_variant *id_variant;
        int r;

        assert(c);
        assert(v);

        /* Events have an "event" key */
        if (sd_json_variant_by_key(v, "event")) {
                (void) qmp_client_dispatch_event(c, v);
                return 1;
        }

        /* Command responses have an "id" key — match against pending async commands */
        id_variant = sd_json_variant_by_key(v, "id");
        if (id_variant) {
                uint64_t id = sd_json_variant_unsigned(id_variant);
                _cleanup_free_ QmpPendingCommand *pending = hashmap_remove(c->pending_commands, UINT64_TO_PTR(id));
                if (!pending) {
                        log_debug("Discarding unmatched QMP response for id %" PRIu64, id);
                        return 1;
                }

                sd_json_variant *result = sd_json_variant_by_key(v, "return");
                if (result) {
                        r = pending->callback(c, result, NULL, 0, pending->userdata);
                        if (r < 0)
                                log_debug_errno(r, "Command callback returned error, ignoring: %m");
                        return 1;
                }

                sd_json_variant *error = sd_json_variant_by_key(v, "error");
                if (error) {
                        _cleanup_free_ char *error_desc = qmp_extract_error_description(error);
                        r = pending->callback(c, NULL, error_desc, -EIO, pending->userdata);
                        if (r < 0)
                                log_debug_errno(r, "Command callback returned error, ignoring: %m");
                        return 1;
                }

                r = pending->callback(c, NULL, NULL, -EPROTO, pending->userdata);
                if (r < 0)
                        log_debug_errno(r, "Command callback returned error, ignoring: %m");
                return 1;
        }

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

        if (!c->connected)
                return 0;

        c->connected = false;

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

QmpClient *qmp_client_close_unref(QmpClient *c) {
        qmp_client_close(c);
        return qmp_client_unref(c);
}

/* Perform a single step of QMP processing. Returns 1 if progress was made, 0 if nothing
 * is available (caller should wait), negative on error. Matches sd-varlink's
 * sd_varlink_process() pattern. When attached to an event loop, enables the defer event
 * source on progress so processing continues on the next event loop iteration. */
int qmp_client_process(QmpClient *c) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert_return(c, -EINVAL);

        if (!c->connected)
                return -ENOTCONN;

        /* 1. Try to parse a complete message from the buffer */
        r = qmp_client_parse_message(c, &v);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse QMP message, disconnecting: %m");
                qmp_client_handle_disconnect(c);
                goto finish;
        }
        if (r > 0) {
                r = qmp_client_dispatch_message(c, v);
                goto finish;
        }

        /* 2. Try to read more data from the fd */
        r = qmp_client_fill_buffer(c);
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

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. The fd is switched
 * to non-blocking immediately. The handshake uses a process+wait loop (fd_wait_for_event)
 * matching sd-varlink's varlink_call_internal() pattern where the caller drives processing
 * directly rather than through the event loop. After the handshake, attaches to sd_event
 * for async operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event) {
        _cleanup_(qmp_client_unrefp) QmpClient *c = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(event, -EINVAL);

        c = new(QmpClient, 1);
        if (!c)
                return -ENOMEM;

        *c = (QmpClient) {
                .n_ref = 1,
                .fd = TAKE_FD(fd),
                .connected = true,
                .next_id = 1,
        };

        r = fd_nonblock(c->fd, true);
        if (r < 0)
                return r;

        /* Handshake: process+wait loop on the non-blocking fd. The event loop is not
         * attached yet — the caller drives processing directly, same as sd-varlink's
         * blocking call pattern (sd_varlink_process + sd_varlink_wait). */
        r = qmp_client_read_greeting(c);
        if (r < 0)
                return r;

        r = qmp_client_call(c, "qmp_capabilities", /* arguments= */ NULL, /* ret_result= */ NULL, /* ret_error_desc= */ NULL);
        if (r < 0)
                return r;

        /* Probe io_uring support. Non-fatal — if the probe fails (e.g. QEMU crashed),
         * supports_io_uring stays false (safe default). */
        r = qmp_client_probe_io_uring(c);
        if (r < 0)
                log_debug_errno(r, "io_uring probe failed, defaulting to no io_uring: %m");

        /* Attach to sd_event for async operation */
        r = qmp_client_attach_event(c, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

static int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(event, -EINVAL);
        assert_return(!c->event, -EBUSY);

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

static void qmp_client_detach_event(QmpClient *c) {
        if (!c)
                return;

        c->defer_event_source = sd_event_source_disable_unref(c->defer_event_source);
        c->io_event_source = sd_event_source_disable_unref(c->io_event_source);
        c->event = sd_event_unref(c->event);
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

int qmp_client_execute_send_fd(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                qmp_command_callback_t callback,
                void *userdata) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        _cleanup_free_ QmpPendingCommand *pending = NULL;
        uint64_t id;
        int r;

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);
        assert_return(fd >= 0, -EBADF);
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

        r = qmp_client_write_json_fd(c, cmd, fd);
        if (r < 0) {
                hashmap_remove(c->pending_commands, UINT64_TO_PTR(id));
                return r;
        }

        TAKE_PTR(pending);
        return 0;
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

bool qmp_client_has_feature(QmpClient *c, QmpClientFeature feature) {
        return c ? FLAGS_SET(c->features, feature) : false;
}

unsigned qmp_client_next_fdset_id(QmpClient *c) {
        assert(c);
        return c->next_fdset_id++;
}

static QmpClient *qmp_client_destroy(QmpClient *c) {
        if (!c)
                return NULL;

        qmp_client_clear(c);

        free(c->input_buffer);
        free(c->description);
        hashmap_free(c->pending_commands);

        return mfree(c);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(QmpClient, qmp_client, qmp_client_destroy);
