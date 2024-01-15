/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-socket.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "socket-util.h"
#include <sys/socket.h>
#include <sys/uio.h>

void server_open_forward_socket(Server *s) {
        _cleanup_close_ int socket_fd = -EBADF;
        const SocketAddress *addr;
        int family;

        assert(s);
        assert(s->forward_socket_fd < 0);

        addr = &s->forward_address;

        /* if no forwarding address has been set don't open the socket. */
        if (!socket_address_verify(addr, true))
                return;

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

        /* we need a newline after each one + two on the final one */
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

        char lf[] = "\n", lflf[] = "\n\n";
        for (size_t i = 0; i < n_iovec; i++) {
                iov[i * 2] = iovec[i];
                iov[i * 2 + 1] = (struct iovec) {
                        .iov_base = lf,
                        .iov_len = 1
                };
        }
        iov[n - 1] = (struct iovec) {
                .iov_base = lflf,
                .iov_len = 2,
        };

        if (writev(s->forward_socket_fd, iov, n) < 0)
                log_debug("Failed to forward log message over vsock");
}
