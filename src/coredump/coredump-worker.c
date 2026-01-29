/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "coredump-context.h"
#include "coredump-socket.h"
#include "coredump-send.h"
#include "coredump-submit.h"
#include "coredump-worker.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "log.h"
#include "namespace-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "varlink-util.h"

static int send_to_new_container(CoredumpContext *context) {
        int r;

        assert(context);

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, "/run/systemd/io.systemd.Coredump.Container");
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to /run/systemd/io.systemd.Coredump.Container: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to allow passing file descriptor through varlink: %m");

        r = sd_varlink_push_dup_fd(vl, context->input_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to push coredump socket into varlink: %m");
        unsigned index = r;

        return varlink_callbo_and_log(
                        vl,
                        "io.systemd.Coredump.Container.Transfer",
                        /* ret_parameters= */ NULL,
                        SD_JSON_BUILD_PAIR_UNSIGNED("coredumpFileDescriptor", index),
                        SD_JSON_BUILD_PAIR_UNSIGNED("timestamp", context->timestamp));
}

static int send_to_legacy_container(CoredumpContext *context) {
        int r;

        assert(context);

        _cleanup_(coredump_context_done) CoredumpContext container_context = COREDUMP_CONTEXT_NULL;
        container_context.input_fd = TAKE_FD(context->input_fd);
        container_context.timestamp = context->timestamp;
        container_context.forwarded = true;

        r = coredump_context_parse_from_peer(&container_context);
        if (r < 0)
                return r;

        r = coredump_context_build_iovw(&container_context);
        if (r < 0)
                return r;

        return coredump_send(&container_context);
}

static int send_to_container(CoredumpContext *context) {
        int r;

        assert(context);
        assert(pidref_is_set(&context->pidref));

        if (context->same_pidns)
                return 0;

        _cleanup_(pidref_done) PidRef leader = PIDREF_NULL;
        r = namespace_get_leader(&context->pidref, NAMESPACE_PID, &leader);
        if (r < 0)
                return log_debug_errno(r, "Failed to get leader of container pid namespace: %m");

        r = can_forward_coredump(&context->pidref, &leader);
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

        /* First, try to use the new socket client interface. */
        r = namespace_fork(
                        "(container-outer)",
                        "(container-inner)",
                        /* flags= */ 0,
                        pidns_fd,
                        mntns_fd,
                        /* netns_fd= */ -EBADF,
                        userns_fd,
                        root_fd,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process in the container namespace. */
                errno_pipe[0] = safe_close(errno_pipe[0]);
                r = send_to_new_container(context);
                report_errno_and_exit(errno_pipe[1], r);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);
        if (read_errno(errno_pipe[0]) >= 0)
                return 1; /* sent */

        /* Next, let's try to send to the legacy container interface. As it does not support the new request
         * protocol, we need to process that here. */
        r = coredump_process_socket(context);
        if (r < 0)
                return r;

        errno_pipe[0] = safe_close(errno_pipe[0]);
        if (pipe2(errno_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = namespace_fork(
                        "(container-outer)",
                        "(container-inner)",
                        /* flags= */ 0,
                        pidns_fd,
                        mntns_fd,
                        /* netns_fd= */ -EBADF,
                        userns_fd,
                        root_fd,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child process in the container namespace. */
                errno_pipe[0] = safe_close(errno_pipe[0]);
                r = send_to_legacy_container(context);
                report_errno_and_exit(errno_pipe[1], r);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);
        r = read_errno(errno_pipe[0]);
        if (r < 0)
                return r;

        return 1; /* sent */
}

int coredump_worker(const CoredumpConfig *config, int coredump_fd, usec_t timestamp) {
        int r;

        assert(config);
        assert(coredump_fd >= 0);

        /* This invalidates the input file descriptor even on failure. */

        LogTarget saved_target = _LOG_TARGET_INVALID;
        if (!log_on_console()) {
                saved_target = log_get_target();
                log_set_target_and_open(LOG_TARGET_KMSG);
        }

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_message =
                notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        /* Set higher OOM score, we only protect the manager process. */
        r = set_oom_score_adjust(500);
        if (r < 0)
                log_debug_errno(r, "Failed to reset OOM score, ignoring: %m");

        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        context.input_fd = TAKE_FD(coredump_fd);
        context.timestamp = timestamp;

        r = coredump_context_parse_from_peer(&context);
        if (r < 0)
                return r;

        if (!coredump_context_is_journald(&context))
                log_set_target_and_open(saved_target);

        /* Log minimal metadata now, so it is not lost if the system is about to shut down. */
        _cleanup_free_ char *signal_msg = NULL;
        if (SIGNAL_VALID(context.signo))
                (void) asprintf(&signal_msg, " with signal %i/%s", context.signo, signal_to_string(context.signo));
        log_info("Process "PID_FMT" (%s) of user "UID_FMT" terminated abnormally%s, processing...",
                 context.pidref.pid, context.comm, context.uid, strempty(signal_msg));

        if (send_to_container(&context) > 0)
                return 0;

        r = coredump_process_socket(&context);
        if (r < 0)
                return r;

        return coredump_submit(config, &context);
}
