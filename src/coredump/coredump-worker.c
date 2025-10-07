/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-socket.h"
#include "coredump-send.h"
#include "coredump-worker.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "namespace-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "varlink-util.h"

static int can_forward_coredump(PidRef *pidref, PidRef *leader) {
        int r;

        assert(pidref_is_set(pidref));
        assert(pidref_is_set(leader));

        if (pidref_equal(pidref, leader)) {
                log_debug("The system service manager is crashed.");
                return false;
        }

        /* Check if the PID1 in the namespace is still running. */
        r = pidref_kill(leader, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send kill(0) to the service manager, maybe it is crashed, ignoring: %m");

        if (leader->fd >= 0) {
                struct pidfd_info info = {
                        .mask = PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP,
                };

                r = pidfd_get_info(leader->fd, &info);
                if (r < 0)
                        return log_debug_errno(r, "ioctl(PIDFD_GET_INFO) for the service manager failed, maybe crashed, ignoring: %m");

                if (FLAGS_SET(info.mask, PIDFD_INFO_EXIT)) {
                        log_debug("PID1 is already exited.");
                        return false;
                }

                if (FLAGS_SET(info.mask, PIDFD_INFO_COREDUMP) && FLAGS_SET(info.coredump_mask, PIDFD_COREDUMPED)) {
                        log_debug("PID1 is already dumped core.");
                        return false;
                }
        }

        r = pidref_can_forward_coredump(leader);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if we can forward coredump to container: %m");

        return r;
}

static int send_to_new_container(int coredump_fd, bool request_mode, usec_t timestamp) {
        int r;

        assert(coredump_fd >= 0);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Coredump.Client");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to /run/systemd/io.systemd.Coredump.Client: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to allow passing file descriptor through varlink: %m");

        (void) sd_varlink_set_description(vl, "varlink-coredump-client");

        r = sd_varlink_push_dup_fd(vl, coredump_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to push coredump socket into varlink: %m");
        unsigned index = r;

        return varlink_callb_and_log(vl, "io.systemd.Coredump.Client.Submit", /* ret_parameters= */ NULL,
                                     SD_JSON_BUILD_PAIR_UNSIGNED("coredumpFileDescriptor", index),
                                     SD_JSON_BUILD_PAIR_UNSIGNED("timestamp", timestamp),
                                     SD_JSON_BUILD_PAIR_BOOLEAN("requestMode", request_mode));
}

static int send_to_legacy_container(int coredump_fd, bool request_mode, usec_t timestamp) {
        int r;

        assert(coredump_fd >= 0);

        /* This invalidates the passed coredump_fd even on failure. */

        CoredumpConfig config;
        (void) coredump_parse_config(&config);

        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        context.input_fd = coredump_fd;
        context.timestamp = timestamp;
        context.forwarded = true;

        /* The legacy interface does not support the new request protocol. We need to do that here. */
        if (request_mode) {
                (void) fd_nonblock(coredump_fd, true);

                r = coredump_process_request(coredump_fd);
                if (r < 0)
                        return r;
        }

        (void) fd_nonblock(coredump_fd, false);

        r = coredump_context_parse_from_peer(&context);
        if (r < 0)
                return r;

        /* FIXME: we cannot get exit code through PIDFD_GET_INFO, as the process has not exited yet.
         * But, the old coredump client requires COREDUMP_SIGNAL= field set. Let's set a fake signal. */
        if (!SIGNAL_VALID(context.signo))
                context.signo = SIGABRT;

        r = coredump_context_build_iovw(&context);
        if (r < 0)
                return r;

        return coredump_send(&context);
}

static int send_to_container(int coredump_fd, bool request_mode, usec_t timestamp) {
        int r;

        assert(coredump_fd >= 0);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = getpeerpidref(coredump_fd, &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer pidref: %m");

        r = pidref_in_same_namespace(&pidref, NULL, NAMESPACE_PID);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if the crashed process is belonging to our pid namespace: %m");
        if (r > 0)
                return 0; /* In the same PID namespace, not necessary to forward. */

        _cleanup_(pidref_done) PidRef leader = PIDREF_NULL;
        r = namespace_get_leader(&pidref, NAMESPACE_PID, &leader);
        if (r < 0)
                return log_debug_errno(r, "Failed to get leader of container pid namespace: %m");

        r = can_forward_coredump(&pidref, &leader);
        if (r <= 0)
                return r;

        _cleanup_close_ int pidns_fd = -EBADF, mntns_fd = -EBADF, userns_fd = -EBADF, root_fd = -EBADF;
        r = pidref_namespace_open(
                        &leader,
                        &pidns_fd,
                        &mntns_fd,
                        /* ret_netns_fd= */ NULL,
                        &userns_fd,
                        &root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open container namespace: %m");

        _cleanup_close_pair_ int errno_pipe[2] = EBADF_PAIR;
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = namespace_fork(
                        "(container-outer)",
                        "(container-inner)",
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        /* flags= */ 0,
                        pidns_fd,
                        mntns_fd,
                        /* netns_fd= */ -EBADF,
                        userns_fd,
                        root_fd,
                        /* ret_pid= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process in the container namespace. */
                errno_pipe[0] = safe_close(errno_pipe[0]);

                /* First, try to use the new socket client interface. */
                if (send_to_new_container(coredump_fd, request_mode, timestamp) >= 0)
                        return 0;

                /* If not, try to use the legacy socket client interface. */
                r = send_to_legacy_container(coredump_fd, request_mode, timestamp);
                report_errno_and_exit(errno_pipe[1], r);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);

        r = read_errno(errno_pipe[0]);
        if (r < 0)
                return r;

        return 1; /* sent */
}

int coredump_worker(
                const CoredumpConfig *config,
                int coredump_fd, /* This invalidates the file descriptor even on failure. */
                bool request_mode,
                usec_t timestamp) {

        _cleanup_close_ int fd = ASSERT_FD(coredump_fd);
        int r;

        assert(config);

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message =
                notify_message = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        /* Set higher OOM score, we only protect the manager process. */
        r = set_oom_score_adjust(500);
        if (r < 0)
                log_debug_errno(r, "Failed to reset OOM score, ignoring: %m");

        if (send_to_container(fd, request_mode, timestamp) > 0)
                return 0;

        return coredump_process_socket(config, TAKE_FD(fd), request_mode, timestamp, /* forwarded= */ false);
}
