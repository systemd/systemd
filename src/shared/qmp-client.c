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

        unsigned next_fdset_id;   /* monotonic fdset-id allocator for add-fd */

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

        /* NB: loop_write() with timeout=0 returns -EAGAIN immediately on a non-blocking fd if the
         * socket buffer is full. In async mode (after qmp_client_start_async()) this means a write could
         * theoretically fail. In practice QMP commands are tiny (< 1KB) and the kernel socket buffer is
         * 128KB+, so this cannot happen in any realistic scenario. If this ever becomes a problem, the
         * fix is buffered writes with EPOLLOUT on the sd-event source. */
        return loop_write(c->fd, json_str, SIZE_MAX);
}

static int qmp_client_write_json(QmpClient *c, sd_json_variant *v) {
        return qmp_client_write_json_fd(c, v, -EBADF);
}

static void qmp_client_dispatch_event(QmpClient *c, sd_json_variant *v) {
        assert(c);
        assert(v);

        if (!c->event_callback)
                return;

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
                return;

        c->event_callback(c, p.event, p.data, c->event_userdata);
}

static int qmp_extract_error_class(sd_json_variant *error, char **ret) {
        assert(ret);

        sd_json_variant *class = sd_json_variant_by_key(error, "class");
        if (!class) {
                *ret = NULL;
                return 0;
        }

        char *s = strdup(sd_json_variant_string(class));
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
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

/* Wait for a response matching the given id. Events are dispatched, non-matching responses
 * are discarded. Single response-parsing path for all blocking callers. Returns 0 on success,
 * -EIO on QMP error (class in reterr_error), negative errno on transport failure. */
static int qmp_client_wait_response(
                QmpClient *c,
                uint64_t id,
                sd_json_variant **ret_result,
                char **reterr_error) {

        int r;

        assert(c);

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
                if (!resp_id || sd_json_variant_unsigned(resp_id) != id)
                        continue;

                sd_json_variant *result = sd_json_variant_by_key(response, "return");
                if (result) {
                        if (ret_result)
                                *ret_result = sd_json_variant_ref(result);
                        return 0;
                }

                sd_json_variant *error = sd_json_variant_by_key(response, "error");
                if (error) {
                        if (reterr_error)
                                (void) qmp_extract_error_class(error, reterr_error);
                        return -EIO;
                }

                return -EPROTO;
        }
}

/* Send a QMP command and wait for the matching response. Used only during the initial handshake. */
static int qmp_client_handshake_call(QmpClient *c, const char *command, sd_json_variant *arguments) {
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

        return qmp_client_wait_response(c, id, NULL, NULL);
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

        c->event_callback(c, "SHUTDOWN", data, c->event_userdata);
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
                if (r == -EAGAIN)
                        break;
                if (r < 0) {
                        if (ERRNO_IS_DISCONNECT(r))
                                got_eof = true;
                        else
                                log_debug_errno(r, "Failed to fill QMP buffer: %m");
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
 * for success. The fd remains in blocking mode for subsequent qmp_client_call() invocations; call
 * qmp_client_start_async() to switch to non-blocking event-driven operation. */
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

        /* Phase 1: Blocking handshake. The fd is in blocking mode at this point — this is fine because
         * we are talking to a trusted peer (our own QEMU child over a socketpair we created), same
         * pattern as nspawn's barrier synchronization before entering sd_event_loop(). Read the QMP
         * greeting, then send qmp_capabilities. If QEMU dies during this, read() returns 0 (EOF). */
        r = qmp_client_read_greeting(c);
        if (r < 0)
                return r;

        r = qmp_client_handshake_call(c, "qmp_capabilities", NULL);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(c);
        return 0;
}

/* Switch from blocking (Phase 1) to async (Phase 2) mode. Must be called after all blocking
 * setup calls (qmp_client_call, drive configuration, cont) are complete. Switches the fd
 * to non-blocking and attaches an I/O event source for processing async events. */
int qmp_client_start_async(QmpClient *c) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(!c->io_event_source, -EALREADY);

        if (!c->connected)
                return -ENOTCONN;

        r = fd_nonblock(c->fd, true);
        if (r < 0)
                return r;

        r = sd_event_add_io(c->event, &c->io_event_source, c->fd, EPOLLIN, qmp_client_io_callback, c);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(c->io_event_source, "qmp-client-io");
        return 0;
}

/* Execute a QMP command synchronously (blocking), optionally sending an FD as SCM_RIGHTS
 * ancillary data alongside the command message. Only valid during Phase 1, before
 * qmp_client_start_async(). Returns the result JSON on success, -EIO on QMP error
 * (with error class in reterr_error), negative errno on transport failure. */
static int qmp_client_call_full(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                sd_json_variant **ret_result,
                char **reterr_error) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *cmd = NULL;
        uint64_t id;
        int r;

        assert(c);
        assert(command);
        assert(!c->io_event_source);

        if (!c->connected)
                return -ENOTCONN;

        r = qmp_client_build_command(c, command, arguments, &cmd, &id);
        if (r < 0)
                return r;

        r = qmp_client_write_json_fd(c, cmd, fd);
        if (r < 0)
                return r;

        return qmp_client_wait_response(c, id, ret_result, reterr_error);
}

int qmp_client_call(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                char **reterr_error) {

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);
        assert_return(!c->io_event_source, -EBUSY);

        return qmp_client_call_full(c, command, arguments, /* fd= */ -EBADF, ret_result, reterr_error);
}

int qmp_client_call_send_fd(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                sd_json_variant **ret_result,
                char **reterr_error) {

        assert_return(c, -EINVAL);
        assert_return(command, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(!c->io_event_source, -EBUSY);

        return qmp_client_call_full(c, command, arguments, fd, ret_result, reterr_error);
}

static int qmp_client_fdset_add_fd_internal(QmpClient *c, unsigned fdset_id, int fd) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *args = NULL;
        _cleanup_free_ char *error_class = NULL;
        int r;

        r = sd_json_buildo(&args, SD_JSON_BUILD_PAIR_UNSIGNED("fdset-id", fdset_id));
        if (r < 0)
                return r;

        r = qmp_client_call_send_fd(c, "add-fd", args, fd, /* ret_result= */ NULL, &error_class);
        if (r < 0)
                return log_error_errno(r, "Failed to pass fd to QEMU via add-fd (fdset %u): %s",
                                       fdset_id, strna(error_class));
        return 0;
}

int qmp_client_fdset_new(QmpClient *c, int fd, QmpFdset *ret) {
        _cleanup_free_ char *path = NULL;
        unsigned id;
        int r;

        assert_return(c, -EINVAL);
        assert_return(fd >= 0, -EBADF);
        assert_return(ret, -EINVAL);

        id = c->next_fdset_id++;

        r = qmp_client_fdset_add_fd_internal(c, id, fd);
        if (r < 0)
                return r;

        if (asprintf(&path, "/dev/fdset/%u", id) < 0)
                return log_oom();

        *ret = (QmpFdset) {
                .id   = id,
                .path = TAKE_PTR(path),
        };
        return 0;
}

int qmp_client_fdset_add_fd(QmpClient *c, QmpFdset *fdset, int fd) {
        assert_return(c, -EINVAL);
        assert_return(fdset, -EINVAL);
        assert_return(fdset->path, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        return qmp_client_fdset_add_fd_internal(c, fdset->id, fd);
}


int qmp_client_job_wait(QmpClient *c, const char *job_id, char **reterr_error) {
        int r;

        assert_return(c, -EINVAL);
        assert_return(job_id, -EINVAL);
        assert_return(!c->io_event_source, -EBUSY);

        if (!c->connected)
                return -ENOTCONN;

        /* Read messages until we see JOB_STATUS_CHANGE with our job reaching "concluded".
         * QEMU job transitions: created → running → waiting → pending → concluded (success)
         * or created → running → aborting → concluded (failure). blockdev-create uses
         * auto_dismiss=false, so the job remains in concluded state until we dismiss it. */
        for (;;) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *msg = NULL;

                r = qmp_client_read_message(c, &msg);
                if (r < 0)
                        return r;

                /* Skip non-event messages (shouldn't arrive during job wait) */
                if (!sd_json_variant_by_key(msg, "event"))
                        continue;

                sd_json_variant *data = sd_json_variant_by_key(msg, "data");
                const char *event = sd_json_variant_string(sd_json_variant_by_key(msg, "event"));

                if (streq_ptr(event, "JOB_STATUS_CHANGE") && data) {
                        const char *id = sd_json_variant_string(sd_json_variant_by_key(data, "id"));
                        const char *status = sd_json_variant_string(sd_json_variant_by_key(data, "status"));

                        if (streq_ptr(id, job_id) && streq_ptr(status, "concluded"))
                                break;

                        if (streq_ptr(id, job_id))
                                continue; /* Our job but not concluded yet */
                }

                /* Dispatch unrelated events to the event callback */
                qmp_client_dispatch_event(c, msg);
        }

        /* Job concluded. Query its error status — the job is guaranteed to still exist
         * because blockdev-create sets auto_dismiss=false. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jobs = NULL;
        _cleanup_free_ char *error_class = NULL;
        const char *job_error = NULL;

        r = qmp_client_call(c, "query-jobs", /* arguments= */ NULL, &jobs, &error_class);
        if (r < 0)
                return log_debug_errno(r, "Failed to query jobs after conclusion: %s", strna(error_class));

        bool found = false;
        sd_json_variant *entry;
        JSON_VARIANT_ARRAY_FOREACH(entry, jobs) {
                sd_json_variant *id = sd_json_variant_by_key(entry, "id");
                if (!streq_ptr(sd_json_variant_string(id), job_id))
                        continue;

                sd_json_variant *err = sd_json_variant_by_key(entry, "error");
                job_error = sd_json_variant_string(err);
                found = true;
                break;
        }

        if (!found)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "Job '%s' vanished from query-jobs despite auto_dismiss=false", job_id);

        /* Dismiss the concluded job */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dismiss_args = NULL;
        (void) sd_json_buildo(&dismiss_args, SD_JSON_BUILD_PAIR_STRING("id", job_id));
        (void) qmp_client_call(c, "job-dismiss", dismiss_args, /* ret_result= */ NULL, /* reterr_error= */ NULL);

        if (job_error) {
                if (reterr_error) {
                        char *s = strdup(job_error);
                        if (!s)
                                return -ENOMEM;
                        *reterr_error = s;
                }
                return -EIO;
        }

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

sd_event *qmp_client_get_event(QmpClient *c) {
        return c ? c->event : NULL;
}

QmpClient *qmp_client_free(QmpClient *c) {
        if (!c)
                return NULL;

        /* Ensure pending async callbacks are notified before teardown */
        qmp_client_handle_disconnect(c);

        c->io_event_source = sd_event_source_disable_unref(c->io_event_source);
        c->event = sd_event_unref(c->event);
        c->fd = safe_close(c->fd);
        free(c->input_buffer);
        hashmap_free(c->pending_commands);

        return mfree(c);
}
