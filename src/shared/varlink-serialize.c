/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fdset.h"
#include "log.h"
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
