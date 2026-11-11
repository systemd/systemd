/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "alloc-util.h"
#include "data-fd-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "iovec-util.h"
#include "log.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "serialize.h"
#include "socket-util.h"
#include "string-util.h"
#include "varlink-internal.h"
#include "varlink-serialize.h"

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

int varlink_server_serialize_connections(sd_varlink_server *s, const char *key, FILE *f, FDSet *fds) {
        _cleanup_(iovec_done_erase) struct iovec data = {};
        _cleanup_free_ char *value = NULL;
        size_t n_conn_fds = 0;
        int *conn_fds = NULL, r;

        assert(key);
        assert(f);
        assert(fds);

        if (!s || sd_varlink_server_current_connections(s) == 0)
                return 0;

        CLEANUP_ARRAY(conn_fds, n_conn_fds, close_many_and_free);

        r = sd_varlink_server_serialize(s, &data.iov_base, &data.iov_len, &conn_fds, &n_conn_fds);
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to serialize varlink connections: %m");

        /* The serialization might be large (it contains all unprocessed input and unwritten output of all
         * connections), and serialization lines are limited to LONG_LINE_MAX, hence pass it in a memfd
         * instead of inline. Since it might contain sensitive data, erase our copy afterwards. */
        int data_fd = data_fd_from_iovec(key, &data);
        if (data_fd < 0)
                return varlink_server_log_errno(s, data_fd, "Failed to allocate memfd for varlink connection serialization: %m");

        r = fdset_consume(fds, data_fd);
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to add varlink connection serialization memfd to fd set: %m");

        if (asprintf(&value, "%i", data_fd) < 0)
                return log_oom_debug();

        /* The memfd is followed by the fds referenced by the serialization, in order */
        FOREACH_ARRAY(i, conn_fds, n_conn_fds) {
                int fd = TAKE_FD(*i);

                r = fdset_consume(fds, fd);
                if (r < 0)
                        return varlink_server_log_errno(s, r, "Failed to add varlink connection fd to fd set: %m");

                if (strextendf(&value, " %i", fd) < 0)
                        return log_oom_debug();
        }

        return serialize_item(f, key, value);
}

int varlink_server_deserialize_connections(sd_varlink_server *s, const char *value, FDSet *fds) {
        _cleanup_close_ int data_fd = -EBADF;
        size_t n_conn_fds = 0;
        uint64_t size;
        int *conn_fds = NULL, r;

        /* This function expects the value of a serialization line written by
         * varlink_server_serialize_connections() */

        assert(s);
        assert(value);
        assert(fds);

        CLEANUP_ARRAY(conn_fds, n_conn_fds, close_many_and_free);

        for (const char *p = value;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, /* separators= */ NULL, /* flags= */ 0);
                if (r < 0)
                        return varlink_server_log_errno(s, r, "Failed to parse varlink connection serialization: %s", value);
                if (r == 0)
                        break;

                _cleanup_close_ int fd = deserialize_fd(fds, word);
                if (fd < 0)
                        return varlink_server_log_errno(s, fd, "Failed to deserialize varlink connection fd: %m");

                if (data_fd < 0) {
                        data_fd = TAKE_FD(fd);
                        continue;
                }

                if (!GREEDY_REALLOC(conn_fds, n_conn_fds + 1))
                        return log_oom_debug();

                conn_fds[n_conn_fds++] = TAKE_FD(fd);
        }

        if (data_fd < 0)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBADMSG), "Varlink connection serialization lacks memfd, refusing.");

        /* Map the memfd instead of reading it, since it might be large (it contains all unprocessed input
         * and unwritten output of all connections), and this way we neither need to copy it nor are
         * subject to the size limits of read_full_file(). */
        r = memfd_get_size(data_fd, &size);
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to determine size of varlink connection serialization: %m");
        if (size == 0)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBADMSG), "Varlink connection serialization is empty, refusing.");
        if (size > SIZE_MAX)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EFBIG), "Varlink connection serialization too large, refusing.");

        void *data = mmap(/* addr= */ NULL, size, PROT_READ, MAP_PRIVATE, data_fd, /* offset= */ 0);
        if (data == MAP_FAILED)
                return varlink_server_log_errno(s, errno, "Failed to map varlink connection serialization: %m");

        /* On success this closes the passed fds and sets them to -EBADF, which our cleanup handler
         * then ignores */
        r = sd_varlink_server_deserialize(s, data, size, conn_fds, n_conn_fds);
        assert_se(munmap(data, size) >= 0);
        return r;
}

int varlink_serialize_connection_id(sd_varlink *link, const char *key, FILE *f) {
        const char *id;
        int r;

        assert(key);
        assert(f);

        if (!link)
                return 0;

        r = sd_varlink_get_connection_id(link, &id);
        if (r == -ENOTCONN) {
                /* The peer went away already, nothing to pass on */
                varlink_log(link, "Connection is disconnected, not serializing its identifier.");
                return 0;
        }
        if (r < 0)
                return varlink_log_errno(link, r, "Failed to get varlink connection id: %m");

        return serialize_item(f, key, id);
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
