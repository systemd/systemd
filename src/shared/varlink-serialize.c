/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "fdset.h"
#include "log.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "varlink-internal.h"
#include "varlink-serialize.h"

int varlink_server_serialize(sd_varlink_server *s, FILE *f, FDSet *fds) {
        assert(f);
        assert(fds);

        if (!s)
                return 0;

        LIST_FOREACH(sockets, ss, s->sockets) {
                int copy;

                assert(ss->address);
                assert(ss->fd >= 0);

                fprintf(f, "varlink-server-socket-address=%s", ss->address);

                /* If we fail to serialize the fd, it will be considered an error during deserialization */
                copy = fdset_put_dup(fds, ss->fd);
                if (copy < 0)
                        return copy;

                fprintf(f, " varlink-server-socket-fd=%i", copy);

                fputc('\n', f);
        }

        return 0;
}

int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds) {
        _cleanup_(varlink_server_socket_freep) VarlinkServerSocket *ss = NULL;
        _cleanup_free_ char *address = NULL;
        const char *v = ASSERT_PTR(value);
        int r, fd = -EBADF;
        char *buf;
        size_t n;

        assert(s);
        assert(fds);

        n = strcspn(v, " ");
        address = strndup(v, n);
        if (!address)
                return log_oom_debug();

        if (v[n] != ' ')
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to deserialize sd_varlink_server_socket: %s", value);
        v = startswith(v + n + 1, "varlink-server-socket-fd=");
        if (!v)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to deserialize VarlinkServerSocket fd: %s", value);

        n = strcspn(v, " ");
        buf = strndupa_safe(v, n);

        fd = parse_fd(buf);
        if (fd < 0)
                return varlink_server_log_errno(s, fd, "Unable to parse VarlinkServerSocket varlink-server-socket-fd=%s: %m", buf);
        if (!fdset_contains(fds, fd))
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBADF),
                                       "VarlinkServerSocket varlink-server-socket-fd= has unknown fd: %d", fd);

        ss = new(VarlinkServerSocket, 1);
        if (!ss)
                return log_oom_debug();

        *ss = (VarlinkServerSocket) {
                .server = s,
                .address = TAKE_PTR(address),
                .fd = fdset_remove(fds, fd),
        };

        r = varlink_server_add_socket_event_source(s, ss);
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to add VarlinkServerSocket event source to the event loop: %m");

        LIST_PREPEND(sockets, s->sockets, TAKE_PTR(ss));
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
