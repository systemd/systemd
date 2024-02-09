/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <sys/uio.h>

#include "fd-util.h"
#include "iovec-util.h"
#include "journald-socket.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "socket-util.h"

void server_open_forward_socket(Server *s) {
        _cleanup_close_ int socket_fd = -EBADF;
        const SocketAddress *addr;
        int family;

        assert(s);
        assert(s->forward_socket_fd < 0);

        addr = &s->forward_to_socket;

        family = socket_address_family(addr);

        if (!IN_SET(family, AF_UNIX, AF_INET, AF_INET6, AF_VSOCK)) {
                log_debug("Unsupported socket type for forward socket: %d", family);
                return;
        }

        socket_fd = socket(family, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (socket_fd < 0) {
                log_debug_errno(errno, "Failed to create forward socket, ignoring: %m");
                return;
        }

        if (connect(socket_fd, &addr->sockaddr.sa, addr->size) < 0) {
                log_debug_errno(errno, "Failed to connect to remote address for forwarding, ignoring: %m");
                return;
        }

        s->forward_socket_fd = TAKE_FD(socket_fd);
        log_debug("Successfully connected to remote address for forwarding");
}

void server_forward_socket(
                Server *s,
                const struct iovec *iovec,
                size_t n_iovec,
                int priority) {
        _cleanup_free_ struct iovec *iov_alloc = NULL;
        struct iovec *iov = NULL;

        assert(s);
        assert(iovec);
        assert(n_iovec > 0);

        if (LOG_PRI(priority) > s->max_level_socket)
                return;

        /* only open a forwarding socket if a forwarding address has been set
         * and we are in the main namespace and the forwarding socket is not already open */
        if (s->forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC && !s->namespace && s->forward_socket_fd < 0)
                server_open_forward_socket(s);

        /* if we failed to open a socket just return */
        if (s->forward_socket_fd < 0)
                return;

        /* we need a newline after each iovec */
        size_t n = n_iovec * 2;

        if (n < ALLOCA_MAX / sizeof(struct iovec) / 2)
                iov = newa(struct iovec, n);
        else {
                iov_alloc = new(struct iovec, n);
                if (!iov_alloc) {
                        log_oom();
                        return;
                }

                iov = iov_alloc;
        }

        struct iovec nl = IOVEC_MAKE_STRING("\n");
        size_t iov_idx = 0;
        FOREACH_ARRAY(i, iovec, n_iovec) {
                iov[iov_idx++] = *i;
                iov[iov_idx++] = nl;
        }

        assert(iov_idx == n);

        /* synthesise __REALTIME_TIMESTAMP as the last argument so systemd-journal-upload can receive these export messages
         * Note: this overwrites the last entry in iov which is currently a newline */
        char buf[sizeof("__REALTIME_TIMESTAMP=") + DECIMAL_STR_MAX(usec_t) + 3];
        xsprintf(buf, "\n__REALTIME_TIMESTAMP="USEC_FMT"\n\n", now(CLOCK_REALTIME));
        iov[n - 1] = IOVEC_MAKE_STRING(buf);

        if (writev(s->forward_socket_fd, iov, n) < 0) {
                log_debug_errno(errno, "Failed to forward log message over socket: %m");

                /* if we failed to send once we will probably fail again so wait for a new connection to
                 * establish before attempting to forward again */
                s->forward_socket_fd = safe_close(s->forward_socket_fd);
        }
}
