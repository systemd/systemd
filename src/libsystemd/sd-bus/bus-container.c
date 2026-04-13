/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bus-container.h"
#include "bus-internal.h"
#include "bus-socket.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "log.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"

int container_get_leader(RuntimeScope scope, const char *machine, pid_t *ret) {
        _cleanup_free_ char *p = NULL, *s = NULL, *class = NULL;
        pid_t leader;
        int r;

        assert(machine);
        assert(ret);

        if (streq(machine, ".host")) {
                if (scope == RUNTIME_SCOPE_USER)
                        return -EHOSTDOWN;

                *ret = 1;
                return 0;
        }

        if (!hostname_is_valid(machine, 0))
                return -EINVAL;

        r = runtime_directory_generic(scope, "systemd/machines", &p);
        if (r < 0)
                return r;

        if (!path_extend(&p, machine))
                return -ENOMEM;

        r = parse_env_file(NULL, p,
                           "LEADER", &s,
                           "CLASS", &class);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -ESRCH;

        if (!streq_ptr(class, "container"))
                return -EMEDIUMTYPE;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EBADMSG;

        *ret = leader;
        return 0;
}

static int bus_container_connect_namespace(sd_bus *b, int pidnsfd, int mntnsfd, int usernsfd, int rootfd) {
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        int r;

        if (pipe2(errno_pipe_fd, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = namespace_fork("(sd-buscntrns)", "(sd-buscntr)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_WAIT,
                           pidnsfd, mntnsfd, /* netns_fd= */ -EBADF, usernsfd, rootfd, /* ret= */ NULL);
        if (r == -EPROTO) {
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                int k = read_errno(errno_pipe_fd[0]);
                if (k < 0 && k != -EIO)
                        return k;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to create namespace for (sd-buscntr): %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                r = RET_NERRNO(connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size));
                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        return 0;
}

int bus_container_connect_socket(sd_bus *b) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        int r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->nspid > 0 || b->machine);

        if (b->nspid <= 0) {
                log_debug("sd-bus: connecting bus%s%s to machine %s...",
                          b->description ? " " : "", strempty(b->description), b->machine);

                r = container_get_leader(RUNTIME_SCOPE_USER, b->machine, &b->nspid);
                if (IN_SET(r, -EHOSTDOWN, -ENXIO))
                        r = container_get_leader(RUNTIME_SCOPE_SYSTEM, b->machine, &b->nspid);
                if (r < 0)
                        return r;
        } else
                log_debug("sd-bus: connecting bus%s%s to namespace of PID "PID_FMT"...",
                          b->description ? " " : "", strempty(b->description), b->nspid);

        r = namespace_open(b->nspid, &pidnsfd, &mntnsfd, /* ret_netns_fd= */ NULL, &usernsfd, &rootfd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open namespace of PID "PID_FMT": %m", b->nspid);

        b->input_fd = socket(b->sockaddr.sa.sa_family, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (b->input_fd < 0)
                return log_debug_errno(errno, "Failed to create a socket: %m");

        b->input_fd = fd_move_above_stdio(b->input_fd);

        b->output_fd = b->input_fd;

        bus_socket_setup(b);

        r = are_our_namespaces(pidnsfd, mntnsfd, /* netns_fd= */ -EBADF, usernsfd, rootfd);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if already in PID "PID_FMT" namespaces: %m", b->nspid);
        if (r > 0)
                r = RET_NERRNO(connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size));
        else
                r = bus_container_connect_namespace(b, pidnsfd, mntnsfd, usernsfd, rootfd);
        if (r == -EINPROGRESS)
                return 1;
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to D-Bus socket in namespaces of PID "PID_FMT": %m", b->nspid);

        return bus_socket_start_auth(b);
}
