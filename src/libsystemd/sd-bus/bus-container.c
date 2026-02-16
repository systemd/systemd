/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bus-container.h"
#include "bus-internal.h"
#include "bus-socket.h"
#include "env-file.h"
#include "fd-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "log.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pidref.h"
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

int bus_container_connect_socket(sd_bus *b) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r, error_buf = 0;
        ssize_t n;

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

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_debug_errno(errno, "Failed to create a socket pair: %m");

        r = namespace_fork("(sd-buscntrns)", "(sd-buscntr)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                           pidnsfd, mntnsfd, -1, usernsfd, rootfd, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to create namespace for (sd-buscntr): %m");
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                r = connect(b->input_fd, &b->sockaddr.sa, b->sockaddr_size);
                if (r < 0) {
                        /* Try to send error up */
                        error_buf = errno;
                        (void) write(pair[1], &error_buf, sizeof(error_buf));
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = pidref_wait_for_terminate_and_check("(sd-buscntrns)", &child, 0);
        if (r < 0)
                return r;
        bool nonzero_exit_status = r != EXIT_SUCCESS;

        n = read(pair[0], &error_buf, sizeof(error_buf));
        if (n < 0)
                return log_debug_errno(errno, "Failed to read error status from (sd-buscntr): %m");

        if (n > 0) {
                if (n != sizeof(error_buf))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                               "Read error status of unexpected length %zd from (sd-buscntr).", n);

                if (error_buf < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Got unexpected error status from (sd-buscntr).");

                if (error_buf == EINPROGRESS)
                        return 1;

                if (error_buf > 0)
                        return log_debug_errno(error_buf, "(sd-buscntr) failed to connect to D-Bus socket: %m");
        }

        if (nonzero_exit_status)
                return -EPROTO;

        return bus_socket_start_auth(b);
}
