/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bus-container.h"
#include "bus-internal.h"
#include "bus-socket.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "string-util.h"

int bus_container_connect_socket(sd_bus *b) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_(pidref_done) PidRef child = PIDREF_NULL;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert(b);
        assert(b->input_fd < 0);
        assert(b->output_fd < 0);
        assert(b->nspid > 0 || b->machine);

        if (b->nspid <= 0) {
                log_debug("sd-bus: connecting bus%s%s to machine %s...",
                          b->description ? " " : "", strempty(b->description), b->machine);

                r = container_get_leader(b->machine, &b->nspid);
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
                report_errno_and_exit(pair[1], r);
        }

        pair[1] = safe_close(pair[1]);

        r = pidref_wait_for_terminate_and_check("(sd-buscntrns)", &child, 0);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS) {
                r = read_errno(pair[0]);
                if (r == -EINPROGRESS)
                        return 1;
                if (r < 0)
                        return log_debug_errno(r, "(sd-buscntr) failed to connect to D-Bus socket: %m");
                return -EPROTO;
        }

        return bus_socket_start_auth(b);
}
