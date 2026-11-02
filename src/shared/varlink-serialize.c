/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "log.h"
#include "parse-util.h"
#include "serialize.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-idl-util.h"
#include "varlink-internal.h"
#include "varlink-serialize.h"

int varlink_get_socket_cookie(sd_varlink *v, uint64_t *ret) {
        int r;

        assert(v);
        assert(ret);

        if (v->socket_cookie == 0) {
                int fd = sd_varlink_get_fd(v);
                if (fd < 0)
                        return fd;

                r = socket_get_cookie(fd, &v->socket_cookie);
                if (r < 0)
                        return r;
        }

        *ret = v->socket_cookie;
        return 0;
}

sd_varlink* varlink_server_get_connection(sd_varlink_server *s, uint64_t cookie) {
        if (!s || cookie == 0)
                return NULL;

        LIST_FOREACH(connections, v, s->connections)
                if (v->socket_cookie == cookie)
                        return v;

        return NULL;
}

static int serialize_buffer(FILE *f, const char *key, const void *data, size_t size) {
        const uint8_t *p = data;
        int r;

        /* Repeat ordinary base64 records to keep each line below LONG_LINE_MAX. */
        while (size > 0) {
                size_t n = MIN(size, (size_t) LONG_LINE_MAX / 2);

                r = serialize_item_base64mem(f, key, p, n);
                if (r < 0)
                        return r;

                p += n;
                size -= n;
        }

        return 0;
}

static int deserialize_buffer(const char *value, struct iovec *buffer) {
        _cleanup_(iovec_done) struct iovec chunk = {};
        int r;

        r = unbase64mem(value, &chunk.iov_base, &chunk.iov_len);
        if (r < 0)
                return r;
        if (!iovec_append(buffer, &chunk))
                return -ENOMEM;

        return 0;
}

int varlink_serialize(sd_varlink *v, const char *key, FILE *f, FDSet *fds) {
        _cleanup_free_ char *current = NULL;
        uint64_t cookie;
        int r;

        assert(v);
        assert(key);
        assert(f);
        assert(fds);

        /* Persist suspended streaming calls. The server must be recreated with the same interface and
         * userdata before restoring the connection. The caller must not process the original connection
         * between taking this snapshot and reexecution. */
        if (!v->server || !IN_SET(v->state, VARLINK_PENDING_METHOD_MORE, VARLINK_PENDING_DISCONNECT) || !v->current)
                return -EBUSY;
        if (v->stream.output_queue || v->stream.n_output_fds > 0 || v->n_pushed_fds > 0 ||
            v->previous || v->sentinel)
                return -EOPNOTSUPP;

        r = varlink_get_socket_cookie(v, &cookie);
        if (r < 0)
                return r;

        int socket_fd = sd_varlink_get_fd(v);
        if (socket_fd < 0)
                return socket_fd;

        r = sd_json_variant_format(v->current, /* flags= */ 0, &current);
        if (r < 0)
                return r;

        fprintf(f, "%s\n", key);

        r = serialize_item_format(f, "socket-cookie", "%" PRIu64, cookie);
        if (r < 0)
                return r;

        r = serialize_fd(f, fds, "socket-fd", socket_fd);
        if (r < 0)
                return r;

        r = serialize_buffer(f, "current", current, strlen(current));
        if (r < 0)
                return r;

        r = serialize_buffer(f, "input-buffer",
                             v->stream.input_buffer ? v->stream.input_buffer + v->stream.input_buffer_index : NULL,
                             v->stream.input_buffer_size);
        if (r < 0)
                return r;

        r = serialize_buffer(f, "output-buffer",
                             v->stream.output_buffer ? v->stream.output_buffer + v->stream.output_buffer_index : NULL,
                             v->stream.output_buffer_size);
        if (r < 0)
                return r;

        FOREACH_ARRAY(fd, v->stream.input_fds, v->stream.n_input_fds) {
                r = serialize_fd(f, fds, "input-fd", *fd);
                if (r < 0)
                        return r;
        }

        r = serialize_bool(f, "disconnecting", v->state == VARLINK_PENDING_DISCONNECT);
        if (r < 0)
                return r;

        r = serialize_item_format(f, "stream-flags", "%u", v->stream.flags);
        if (r < 0)
                return r;

        r = serialize_usec(f, "timeout", v->stream.timeout);
        if (r < 0)
                return r;

        fputc('\n', f);
        return 0;
}

typedef struct VarlinkDeserialize {
        uint64_t cookie;
        int socket_fd;
        struct iovec current, input_buffer, output_buffer;
        bool disconnecting;
        unsigned stream_flags;
        usec_t timeout;
        int *fds;
        size_t n_fds;
} VarlinkDeserialize;

static void varlink_deserialize_done(VarlinkDeserialize *p) {
        if (!p)
                return;

        safe_close(p->socket_fd);
        iovec_done(&p->current);
        iovec_done(&p->input_buffer);
        iovec_done(&p->output_buffer);
        close_many(p->fds, p->n_fds);
        free(p->fds);
}

int varlink_deserialize(sd_varlink_server *s, FILE *f, FDSet *fds) {
        _cleanup_(varlink_deserialize_done) VarlinkDeserialize p = {
                .socket_fd = -EBADF,
                .timeout = USEC_INFINITY,
        };
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *current = NULL;
        int ret = 0, r;

        assert(f);
        assert(fds);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *value;

                r = deserialize_read_line(f, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Consume the entire subsection on reload or error, preserving the following manager state. */
                if (!s || ret < 0)
                        continue;

                if ((value = startswith(line, "socket-cookie=")))
                        r = safe_atou64(value, &p.cookie);
                else if ((value = startswith(line, "socket-fd="))) {
                        r = deserialize_fd(fds, value);
                        if (r >= 0) {
                                safe_close(p.socket_fd);
                                p.socket_fd = r;
                        }
                } else if ((value = startswith(line, "current=")))
                        r = deserialize_buffer(value, &p.current);
                else if ((value = startswith(line, "input-buffer=")))
                        r = deserialize_buffer(value, &p.input_buffer);
                else if ((value = startswith(line, "output-buffer=")))
                        r = deserialize_buffer(value, &p.output_buffer);
                else if ((value = startswith(line, "input-fd="))) {
                        _cleanup_close_ int fd = deserialize_fd(fds, value);

                        if (fd < 0)
                                r = fd;
                        else if (!GREEDY_REALLOC_APPEND(p.fds, p.n_fds, &fd, 1))
                                r = -ENOMEM;
                        else {
                                TAKE_FD(fd);
                                r = 0;
                        }
                } else if ((value = startswith(line, "disconnecting="))) {
                        r = parse_boolean(value);
                        if (r >= 0)
                                p.disconnecting = r;
                } else if ((value = startswith(line, "stream-flags=")))
                        r = safe_atou(value, &p.stream_flags);
                else if ((value = startswith(line, "timeout=")))
                        r = deserialize_usec(value, &p.timeout);
                else {
                        log_debug("Unknown Varlink serialization item '%s', ignoring.", line);
                        continue;
                }

                if (r < 0)
                        ret = varlink_server_log_errno(s, r, "Invalid serialized Varlink connection field, skipping connection: %m");
        }

        if (!s || ret < 0)
                return ret;

        const unsigned supported_flags = JSON_STREAM_BOUNDED_READS|JSON_STREAM_INPUT_SENSITIVE|
                JSON_STREAM_ALLOW_FD_PASSING_INPUT|JSON_STREAM_ALLOW_FD_PASSING_OUTPUT|
                JSON_STREAM_GOT_POLLHUP|JSON_STREAM_WRITE_DISCONNECTED|JSON_STREAM_READ_DISCONNECTED|
                JSON_STREAM_PREFER_READ|JSON_STREAM_PREFER_WRITE|JSON_STREAM_OUTPUT_BUFFER_SENSITIVE;
        if (p.cookie == 0 || p.socket_fd < 0 || !iovec_is_set(&p.current) ||
            memchr(p.current.iov_base, 0, p.current.iov_len) ||
            (p.stream_flags & ~supported_flags) != 0)
                return -EINVAL;
        if (varlink_server_get_connection(s, p.cookie))
                return -EEXIST;

        _cleanup_free_ char *text = memdup_suffix0(p.current.iov_base, p.current.iov_len);
        if (!text)
                return -ENOMEM;
        r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &current, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return r;

        const char *method = sd_json_variant_string(sd_json_variant_by_key(current, "method"));
        if (!method || !sd_json_variant_boolean(sd_json_variant_by_key(current, "more")) ||
            sd_json_variant_boolean(sd_json_variant_by_key(current, "oneway")) ||
            sd_json_variant_boolean(sd_json_variant_by_key(current, "upgrade")))
                return -EINVAL;

        sd_varlink_symbol *symbol = hashmap_get(s->symbols, method);
        if (!symbol)
                return -ENOENT;

        r = varlink_idl_validate_method_call(symbol, sd_json_variant_by_key(current, "parameters"),
                                            SD_VARLINK_METHOD_MORE, /* reterr_bad_field= */ NULL);
        if (r < 0)
                return r;

        uint64_t cookie;
        r = socket_get_cookie(p.socket_fd, &cookie);
        if (r < 0)
                return r;
        if (cookie != p.cookie)
                return -EINVAL;

        sd_varlink *v;
        r = sd_varlink_server_add_connection(s, p.socket_fd, &v);
        if (r < 0)
                return r;
        TAKE_FD(p.socket_fd);

        _cleanup_(sd_varlink_close_unrefp) sd_varlink *connection = sd_varlink_ref(v);
        if (p.input_buffer.iov_len > v->stream.buffer_max || p.output_buffer.iov_len > v->stream.buffer_max)
                return -ENOBUFS;

        v->socket_cookie = cookie;
        v->current = TAKE_PTR(current);
        v->current_method = symbol;
        v->state = p.disconnecting ? VARLINK_PENDING_DISCONNECT : VARLINK_PENDING_METHOD_MORE;
        v->stream.flags = p.stream_flags;
        v->stream.timeout = p.timeout;
        v->stream.input_buffer = TAKE_PTR(p.input_buffer.iov_base);
        v->stream.input_buffer_size = v->stream.input_buffer_unscanned = p.input_buffer.iov_len;
        v->stream.output_buffer = TAKE_PTR(p.output_buffer.iov_base);
        v->stream.output_buffer_size = p.output_buffer.iov_len;
        v->stream.input_fds = TAKE_PTR(p.fds);
        v->stream.n_input_fds = p.n_fds;
        p.n_fds = 0;

        sd_varlink_unref(TAKE_PTR(connection)); /* Leave the server's reference in place. */
        return 0;
}

int varlink_server_serialize(sd_varlink_server *s, const char *name, FILE *f, FDSet *fds) {
        assert(f);
        assert(fds);

        if (!s)
                return 0;

        const char *prefix = name ? strjoina("varlink-server-", name) : "varlink-server";

        LIST_FOREACH(sockets, ss, s->sockets) {
                assert(ss->address);
                assert(ss->fd >= 0);

                /* If we fail to serialize the fd, it will be considered an error during deserialization */
                int copy = fdset_put_dup(fds, ss->fd);
                if (copy < 0)
                        return copy;

                fprintf(f, "%s-socket-address=%s varlink-server-socket-fd=%d\n", prefix, ss->address, copy);
        }

        return 0;
}

int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds) {
        _cleanup_free_ char *address = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *v;
        int r;

        /* This function expects a serialization line with "varlink-server(-name)-" prefix stripped! */

        assert(s);
        assert(value);
        assert(fds);

        v = startswith(value, "socket-address=");
        if (!v)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid varlink server serialization entry: %s", value);

        r = extract_first_word(&v, &address, " ", /* flags = */ 0);
        if (r <= 0)
                return varlink_server_log_errno(s, r < 0 ? r : SYNTHETIC_ERRNO(ENODATA),
                                                "Failed to extract socket address from varlink serialization: %s", value);
        if (v)
                v = startswith(v, "varlink-server-socket-fd=");
        if (!v)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBADF),
                                                "Got varlink serialization without socket fd, refusing.");

        fd = deserialize_fd(fds, v);
        if (fd < 0)
                return varlink_server_log_errno(s, fd, "Failed to deserialize varlink socket fd: %m");

        /* NB: varlink_server_socket_free() does not close the fd! */
        _cleanup_(varlink_server_socket_freep) VarlinkServerSocket *ss = NULL;
        ss = new(VarlinkServerSocket, 1);
        if (!ss)
                return log_oom_debug();

        *ss = (VarlinkServerSocket) {
                .server = s,
                .address = TAKE_PTR(address),
                .fd = fd,
        };

        r = varlink_server_add_socket_event_source(s, ss);
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to add VarlinkServerSocket event source to the event loop: %m");

        LIST_PREPEND(sockets, s->sockets, TAKE_PTR(ss));
        TAKE_FD(fd); /* ownership is now transferred to varlink server */

        return 0;
}

bool varlink_server_contains_socket(sd_varlink_server *s, const char *address) {
        int r;

        assert(s);
        assert(address);

        LIST_FOREACH(sockets, ss, s->sockets) {
                r = socket_address_equal_unix(ss->address, address);
                if (r < 0)
                        log_debug_errno(r, "Failed to compare '%s' and '%s', ignoring: %m", ss->address, address);
                if (r > 0)
                        return true;
        }

        return false;
}
