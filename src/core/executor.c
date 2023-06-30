/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "build.h"
#include "env-util.h"
#include "exec-invoke.h"
#include "execute-serialize.h"
#include "execute.h"
#include "exit-status.h"
#include "fdset.h"
#include "fd-util.h"
#include "fileio.h"
#include "getopt-defs.h"
#include "io-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "static-destruct.h"
#include "socket-util.h"

static FILE* arg_serialization = NULL;
static int arg_manager_socket = -EBADF;

STATIC_DESTRUCTOR_REGISTER(arg_serialization, fclosep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "%sSandbox and execute processes.%s\n\n"
               "  -h --help                Show this help and exit\n"
               "     --version             Print version string and exit\n"
               "     --log-target=TARGET   Set log target (console, journal,\n"
               "                                           journal-or-kmsg,\n"
               "                                           kmsg, null)\n"
               "     --log-level=LEVEL     Set log level (debug, info, notice,\n"
               "                                          warning, err, crit,\n"
               "                                          alert, emerg)\n"
               "     --log-color[=BOOL]    Highlight important messages\n"
               "     --log-location[=BOOL] Include code location in messages\n"
               "     --log-time[=BOOL]     Prefix messages with current time\n"
               "     --deserialize=FD      Deserialize process config from FD\n"
               "     --manager-socket=FD   Socket to receive commands from\n"
               "                           the unit manager\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                COMMON_GETOPT_ARGS,
                ARG_VERSION,
                ARG_DESERIALIZE,
                ARG_MANAGER_SOCKET,
        };

        static const struct option options[] = {
                COMMON_GETOPT_OPTIONS,
                { "help",           no_argument,       NULL, 'h'                },
                { "version",        no_argument,       NULL, ARG_VERSION        },
                { "deserialize",    required_argument, NULL, ARG_DESERIALIZE    },
                { "manager-socket", required_argument, NULL, ARG_MANAGER_SOCKET },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_LOG_LEVEL:
                        r = log_set_max_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", optarg);

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log target \"%s\": %m", optarg);

                        break;

                case ARG_LOG_COLOR:
                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log color setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log location setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_location(true);

                        break;

                case ARG_LOG_TIME:
                        if (optarg) {
                                r = log_show_time_from_string(optarg);
                                if (r < 0)
                                        return log_error_errno(r,
                                                        "Failed to parse log time setting \"%s\": %m",
                                                        optarg);
                        } else
                                log_show_time(true);

                        break;

                case ARG_DESERIALIZE: {
                        FILE *f;
                        int fd;

                        fd = parse_fd(optarg);
                        if (fd < 0)
                                return log_error_errno(fd,
                                                "Failed to parse serialization fd \"%s\": %m",
                                                optarg);

                        (void) fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd %d: %m", fd);

                        safe_fclose(arg_serialization);
                        arg_serialization = f;

                        break;
                }

                case ARG_MANAGER_SOCKET: {
                        int fd;

                        fd = parse_fd(optarg);
                        if (fd < 0)
                                return log_error_errno(fd,
                                                "Failed to parse manager socket \"%s\": %m",
                                                optarg);

                        (void) fd_cloexec(fd, true);

                        safe_close(arg_manager_socket);
                        arg_manager_socket = fd;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_serialization && arg_manager_socket < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No serialization nor manager socket specified.");

        if (arg_serialization && arg_manager_socket >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Both serialization and manager socket specified.");

        return 1 /* work to do */;
}

int main(int argc, char *argv[]) {
        _cleanup_fclose_ FILE *serialization = NULL;
        _cleanup_close_ int manager_socket = -EBADF;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_free_ int *fds_array = NULL;
        int exit_status = EXIT_SUCCESS, r;
        size_t n_fds_array = 0;
        _cleanup_(cgroup_context_done) CGroupContext cgroup_context;
        _cleanup_(exec_context_done) ExecContext context;
        _cleanup_(exec_command_done) ExecCommand command = {};
        _cleanup_(exec_params_serialized_done) ExecParameters params = {
                .stdin_fd         = -EBADF,
                .stdout_fd        = -EBADF,
                .stderr_fd        = -EBADF,
                .exec_fd          = -EBADF,
                .user_lookup_fd   = -EBADF,
                .bpf_outer_map_fd = -EBADF,
        };
        _cleanup_(exec_shared_runtime_done) ExecSharedRuntime shared = {
                .netns_storage_socket = PIPE_EBADF,
                .ipcns_storage_socket = PIPE_EBADF,
        };
        _cleanup_(dynamic_creds_done) DynamicCreds dynamic_creds = {};
        _cleanup_(exec_runtime_clear) ExecRuntime runtime = {
                .ephemeral_storage_socket = PIPE_EBADF,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };

        exec_context_init(&context);
        cgroup_context_init(&cgroup_context);

        /* We might be starting the journal itself, we'll be told by the caller what to do */
        log_set_always_reopen_console(true);
        log_set_prohibit_ipc(true);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Now try again if we were told it's fine to use a different target */
        if (log_get_target() != LOG_TARGET_KMSG) {
                log_set_prohibit_ipc(false);
                log_open();
        }

        /* If we are forked directly then we will have all the required FDs already open, create a set to
         * prepare for deserialization. If we are getting a socket instead we'll get them in an array via
         * SCM_RIGHTS. */
        if (arg_serialization) {
                serialization = arg_serialization;

                r = fdset_new_fill(/* filter_cloexec= */ 0, &fdset);
                if (r < 0)
                        return log_error_errno(r, "Failed to create fd set: %m");
        } else if (arg_manager_socket >= 0) {
                _cleanup_close_ int serialization_fd = -EBADF, pidfd = -EBADF;

                manager_socket = arg_manager_socket;

                /* Wait for serialization FD from manager datagram socket */
                r = receive_many_fds(manager_socket, &fds_array, &n_fds_array, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to receive serialization FDs: %m");

                /* There always at the very least the exec FD */
                if (n_fds_array == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Received no FDs from manager socket.");

                /* The memfd with all the data is always the first one */
                serialization_fd = TAKE_FD(fds_array[0]);

                log_debug("Accepting work from worker " PID_FMT, getpid_cached());

                /* Send back pidfd so that systemd knows who took up this job */
                pidfd = pidfd_open(getpid_cached(), 0);
                if (pidfd < 0) {
                        char iov_buffer[DECIMAL_STR_MAX(pid_t) + 1] = {};
                        struct iovec iov = IOVEC_MAKE(iov_buffer, sizeof(iov_buffer) - 1);

                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed to open pidfd: %m");

                        /* Fallback to sending the pid */
                        xsprintf(iov_buffer, "%d", getpid_cached());
                        r = send_one_fd_iov(manager_socket, /* fd= */ -EBADF, &iov, 1, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send pid: %m");
                } else {
                        r = send_one_fd(manager_socket, pidfd, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send pidfd: %m");
                }

                serialization = take_fdopen(&serialization_fd, "r");
                if (!serialization)
                        return log_error_errno(errno, "Failed to open serialization fd: %m");
        } else
                assert_not_reached();

        r = exec_deserialize_invocation(serialization,
                                        fdset,
                                        fds_array,
                                        n_fds_array,
                                        &context,
                                        &command,
                                        &params,
                                        &runtime,
                                        &cgroup_context);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize: %m");

        /* The worker might have been spawned long before it needs to execute a child, so clear the
         * environment and set it to what the manager says it should be */
        r = set_full_environment(context.manager_environment);
        if (r < 0)
                return r;

        arg_serialization = serialization = safe_fclose(serialization);
        arg_manager_socket = manager_socket = safe_close(manager_socket);
        fds_array = mfree(fds_array);
        fdset = fdset_free(fdset);

        r = exec_invoke(&command,
                        &context,
                        &params,
                        &runtime,
                        &cgroup_context,
                        &exit_status);
        if (r < 0) {
                const char *status = ASSERT_PTR(
                                exit_status_to_string(exit_status, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD));

                log_exec_struct_errno(&context, &params, LOG_ERR, r,
                                      "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                      LOG_EXEC_INVOCATION_ID(&params),
                                      LOG_EXEC_MESSAGE(&params, "Failed at step %s spawning %s: %m",
                                                       status, command.path),
                                      "EXECUTABLE=%s", command.path);
        } else
                assert(exit_status == EXIT_SUCCESS);

        return exit_status;
}
