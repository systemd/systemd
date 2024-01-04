/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if_arp.h>
#include <stdio.h>

#include "fd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "missing_socket.h"
#include "parse-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"

static int process_vsock(const char *host, const char *port) {
        int r;

        assert(host);
        assert(port);

        union sockaddr_union sa = {
                .vm.svm_family = AF_VSOCK,
        };

        r = vsock_parse_cid(host, &sa.vm.svm_cid);
        if (r < 0)
                return log_error_errno(r, "Failed to parse vsock cid: %s", host);

        r = vsock_parse_port(port, &sa.vm.svm_port);
        if (r < 0)
                return log_error_errno(r, "Failed to parse vsock port: %s", port);

        _cleanup_close_ int fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate AF_VSOCK socket: %m");

        if (connect(fd, &sa.sa, SOCKADDR_LEN(sa)) < 0)
                return log_error_errno(errno, "Failed to connect to vsock:%u:%u: %m", sa.vm.svm_cid, sa.vm.svm_port);

        /* OpenSSH wants us to send a single byte along with the file descriptor, hence do so */
        r = send_one_fd_iov(STDOUT_FILENO, fd, &IOVEC_NUL_BYTE, /* n_iovec= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_VSOCK socket via STDOUT.");
        return 0;
}

static int process_unix(const char *path) {
        int r;

        assert(path);

        /* We assume the path is absolute unless it starts with a dot (or is already explicitly absolute) */
        _cleanup_free_ char *prefixed = NULL;
        if (!STARTSWITH_SET(path, "/", "./")) {
                prefixed = strjoin("/", path);
                if (!prefixed)
                        return log_oom();

                path = prefixed;
        }

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate AF_UNIX socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to AF_UNIX socket %s: %m", path);

        r = send_one_fd_iov(STDOUT_FILENO, fd, &IOVEC_NUL_BYTE, /* n_iovec= */ 1, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send socket via STDOUT: %m");

        log_debug("Successfully sent AF_UNIX socket via STDOUT.");
        return 0;
}

static int run(int argc, char* argv[]) {

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected two arguments: host and port.");

        const char *host = argv[1], *port = argv[2];

        const char *p = startswith(host, "vsock/");
        if (p)
                return process_vsock(p, port);

        p = startswith(host, "unix/");
        if (p)
                return process_unix(p);

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Don't know how to parse host name specification: %s", host);
}

DEFINE_MAIN_FUNCTION(run);
