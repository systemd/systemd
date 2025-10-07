/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "coredump-config.h"
#include "coredump-context.h"
#include "coredump-socket.h"
#include "coredump-socket-kernel.h"
#include "coredump-send.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "sysctl-util.h"
#include "time-util.h"

#define COREDUMP_SOCKET_PATH           "/run/systemd/coredump-kernel"
#define COREDUMP_REQUEST_SOCKET_PATH   "/run/systemd/coredump-kernel-request"
#define COREDUMP_CONTAINER_SOCKET_PATH "/run/systemd/coredump-container"

static int send_to_new_container(int coredump_fd, bool request_mode, usec_t timestamp) {
        int r;

        assert(coredump_fd >= 0);

        r = access_nofollow(COREDUMP_CONTAINER_SOCKET_PATH, W_OK);
        if (r < 0)
                return log_debug_errno(r, "Cannot find "COREDUMP_CONTAINER_SOCKET_PATH": %m");

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to create socket for container: %m");

        r = connect_unix_path(fd, AT_FDCWD, COREDUMP_CONTAINER_SOCKET_PATH);
        if (r < 0)
                return log_debug_errno(r, "Failed to connect to container coredump socket: %m");

        _cleanup_free_ char *msg = NULL;
        if (asprintf(&msg, "TIMESTAMP=" USEC_FMT, timestamp) < 0)
                return log_oom_debug();

        if (send(fd, msg, strlen(msg) + 1, MSG_NOSIGNAL) < 0)
                return log_debug_errno(errno, "Failed to send message '%s': %m", msg);

        msg = mfree(msg);
        if (asprintf(&msg, "REQUEST=%s", one_zero(request_mode)) < 0)
                return log_oom_debug();

        if (send(fd, msg, strlen(msg) + 1, MSG_NOSIGNAL) < 0)
                return log_debug_errno(errno, "Failed to send message '%s': %m", msg);

        r = send_one_fd(fd, coredump_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send coredump fd: %m");

        return 0;
}

static int send_to_legacy_container(int coredump_fd, bool request_mode, usec_t timestamp) {
        int r;

        assert(coredump_fd >= 0);

        CoredumpConfig config = {};
        (void) coredump_parse_config(&config);

        _cleanup_(coredump_context_done) CoredumpContext context = COREDUMP_CONTEXT_NULL;
        r = coredump_context_build(&config, &context, coredump_fd, timestamp);
        if (r < 0)
                return r;

        /* The legacy interface does not support the new request protocol. We need to do that here. */
        if (request_mode) {
                r = coredump_process_request(coredump_fd);
                if (r < 0)
                        return r;
        }

        return coredump_send(&context, coredump_fd);
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
                return 0;

        _cleanup_(pidref_done) PidRef leader = PIDREF_NULL;
        r = namespace_get_leader(&pidref, NAMESPACE_PID, &leader);
        if (r < 0)
                return log_debug_errno(r, "Failed to get leader of container pid namespace: %m");

        r = pidref_can_forward_coredump(&leader);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if we can forward coredump to container: %m");
        if (r == 0)
                return 0;

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

                /* First, try to use the new container interface. */
                if (send_to_new_container(coredump_fd, request_mode, timestamp) >= 0)
                        return 0;

                /* If not, try to use the legacy container interface. */
                r = send_to_legacy_container(coredump_fd, request_mode, timestamp);
                report_errno_and_exit(errno_pipe[1], r);
        }

        errno_pipe[1] = safe_close(errno_pipe[1]);

        r = read_errno(errno_pipe[0]);
        if (r < 0)
                return r;

        return 1; /* sent */
}

static int get_coredump_socket_mode(void) {
        int r;

        r = RET_NERRNO(access(COREDUMP_REQUEST_SOCKET_PATH, F_OK));
        if (r == -ENOENT)
                return false; /* Non-request mode. */
        if (r < 0)
                return r;

        return 1; /* Request mode. */
}

static int acquire_coredump_fd(int *ret) {
        int r;

        assert(ret);

        r = sd_listen_fds(false);
        if (r < 0)
                return log_error_errno(r, "Failed to determine the number of file descriptors: %m");
        if (r != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Received unexpected number (%i) of file descriptors.", r);

        _cleanup_close_ int fd = SD_LISTEN_FDS_START;

        r = sd_is_socket_unix(fd, SOCK_STREAM, /* listening= */ false, /* path= */ NULL, /* length= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to check if received file descriptor is a valid unix socket: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Received invalid file descriptor.");

        *ret = TAKE_FD(fd);
        return 0;
}

int coredump_process_kernel_socket(int argc, char *argv[]) {
        int r;

        /* On socket mode, the kernel does nor provide the timestamp of the crash. Let's use the
         * timestamp of the invocation. */
        usec_t timestamp = now(CLOCK_REALTIME);

        r = get_coredump_socket_mode();
        if (r < 0)
                return r;
        bool request_mode = r;

        _cleanup_close_ int coredump_fd = -EBADF;
        r = acquire_coredump_fd(&coredump_fd);
        if (r < 0)
                return r;

        if (send_to_container(coredump_fd, request_mode, timestamp) > 0)
                return 0;

        return coredump_process_socket(coredump_fd, request_mode, timestamp);
}

static int set_core_pattern(const char *val) {
        int r;

        /* Since be1e0283021ec73c2eb92839db9a471a068709d9 (v6.17), which is backported as
         * 7d7c1fb85cba5627bbe741fb7539c709435e3848 (v6.16.8), the kernel accepts any invalid patterns. The
         * written pattern is checked only on read, spuriously... Let's first save the original value, then
         * try to write the requested patter, and validate by reading the value. If the validation failed,
         * let's revert to the original value. */

        _cleanup_free_ char *original = NULL;
        (void) sysctl_read("kernel/core_pattern", &original);

        r = sysctl_write("kernel/core_pattern", val);
        if (r >= 0) {
                _cleanup_free_ char *current = NULL;
                r = sysctl_read("kernel/core_pattern", &current);
                if (r >= 0 && streq(current, val))
                        return 0; /* Yay! */
        }

        if (original)
                (void) sysctl_write("kernel/core_pattern", original);

        return r; /* Return the first error. */
}

int coredump_register_socket(int argc, char *argv[]) {
        int r;

        log_setup();

        int request_mode = -1;
        if (argc > 2) {
                const char *s = startswith(argv[2], "--request=");
                if (s) {
                        r = parse_boolean(s);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --request= argument, ignoring: %s", s);
                        else
                                request_mode = r;
                }
        }

        /* First, try to use core pattern with "@@", which is supported since kernel v6.17. */
        if (request_mode != 0) {
                r = set_core_pattern("@@" COREDUMP_SOCKET_PATH);
                if (r >= 0)
                        request_mode = true;
                else if (r != -EINVAL)
                        return log_error_errno(r, "Failed to register coredump socket: %m");
        }

        /* Next, try to use core pattern with "@", which is supported since kernel v6.16. */
        if (request_mode <= 0) {
                r = set_core_pattern("@" COREDUMP_SOCKET_PATH);
                if (r >= 0)
                        request_mode = false;
                else if (r != -EINVAL)
                        return log_error_errno(r, "Failed to register coredump socket: %m");
        }

        if (r < 0) {
                assert(r == -EINVAL);
                log_info("The kernel does not support socket coredump pattern.");
                return 0;
        }

        assert(request_mode >= 0);

        if (request_mode) {
                r = symlink_idempotent(COREDUMP_SOCKET_PATH, COREDUMP_REQUEST_SOCKET_PATH, /* make_relative= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to create symbolic link "COREDUMP_REQUEST_SOCKET_PATH": %m");
        } else {
                if (unlink(COREDUMP_REQUEST_SOCKET_PATH) < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to remove "COREDUMP_REQUEST_SOCKET_PATH": %m");
        }

        return 0;
}
