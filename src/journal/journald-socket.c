/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-socket.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "socket-util.h"
#include <sys/socket.h>
#include <sys/uio.h>

void server_open_vm_forward_socket(Server *s, const SocketAddress *addr) {
        _cleanup_close_ int socket_fd = -EBADF;
        _cleanup_free_ char *pretty = NULL;
        socket_address_print(addr, &pretty);

        assert(s);

        if (s->forward_socket_fd >= 0) {
                log_debug("Forward socket already exists, refusing to open a VM forward socket.");
                return;
        }

        socket_fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (socket_fd < 0) {
                log_debug_errno(errno, "Failed to create AF_VSOCK socket, ignoring: %m");
                return;
        }

        if (connect(socket_fd, &addr->sockaddr.sa, addr->size) < 0) {
                log_debug_errno(errno, "Failed to connect to vsock address for forwarding, ignoring: %m");
                return;
        }

        s->forward_socket_fd = TAKE_FD(socket_fd);
        log_debug("Successfully connected to vsock for forwarding");
}

void server_detect_unix_forward_socket(Server *s) {
        _cleanup_close_ int socket_fd = -EBADF;
        int r;

        assert(s);

        if (s->forward_socket_fd >= 0) {
                log_debug("Forward socket already connected, not detecting unix socket.");
                return;
        }

        socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (socket_fd < 0) {
                log_debug_errno(errno, "Failed to create AF_UNIX socket, ignoring: %m");
                return;
        }

        r = connect_unix_path(socket_fd, AT_FDCWD, "/run/host/journal/socket");
        if (r < 0) {
                log_debug_errno(r, "Failed to connect to /run/systemd/journal/stdout, ignoring: %m");
                return;
        }

        s->forward_socket_fd = TAKE_FD(socket_fd);
        log_debug("Successfully connected to unix socket for forwarding");
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
