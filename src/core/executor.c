/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "argv-util.h"
#include "build.h"
#include "capability-util.h"
#include "cgroup.h"
#include "dynamic-user.h"
#include "exec-invoke.h"
#include "execute.h"
#include "execute-serialize.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-table.h"
#include "label-util.h"
#include "log.h"
#include "options.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "selinux-util.h"
#include "static-destruct.h"

static FILE *arg_serialization = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_serialization, fclosep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%s [OPTIONS...]\n\n"
               "%sSandbox and execute processes.%s\n\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_LOG_LEVEL:
                        r = log_set_max_level_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", arg);
                        break;

                OPTION_COMMON_LOG_TARGET:
                        r = log_set_target_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log target \"%s\": %m", arg);
                        break;

                OPTION_COMMON_LOG_COLOR:
                        r = log_show_color_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log color setting \"%s\": %m", arg);
                        break;

                OPTION_COMMON_LOG_LOCATION:
                        r = log_show_location_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log location setting \"%s\": %m", arg);
                        break;

                OPTION_COMMON_LOG_TIME:
                        r = log_show_time_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log time setting \"%s\": %m", arg);
                        break;

                OPTION_LONG("deserialize", "FD", "Deserialize process config from FD"): {
                        int fd = parse_fd(arg);
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to parse serialization fd \"%s\": %m", arg);

                        /* Set O_CLOEXEC and as a side effect, verify that the fd is valid. */
                        r = fd_cloexec(fd, /* cloexec= */ true);
                        if (r == -EBADF)
                                return log_error_errno(r, "Serialization fd %d is not valid.", fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set serialization fd %d to close-on-exec: %m",
                                                       fd);

                        FILE *f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd %d: %m", fd);

                        safe_fclose(arg_serialization);
                        arg_serialization = f;
                        break;
                }
                }

        if (!arg_serialization)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No serialization fd specified.");

        return 1 /* work to do */;
}

static int run(int argc, char *argv[]) {
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        _cleanup_(cgroup_context_done) CGroupContext cgroup_context = {};
        _cleanup_(exec_context_done) ExecContext context = {};
        _cleanup_(exec_command_done) ExecCommand command = {};
        _cleanup_(exec_params_deep_clear) ExecParameters params = EXEC_PARAMETERS_INIT(/* flags= */ 0);
        _cleanup_(exec_shared_runtime_done) ExecSharedRuntime shared = {
                .userns_storage_socket = EBADF_PAIR,
                .netns_storage_socket = EBADF_PAIR,
                .ipcns_storage_socket = EBADF_PAIR,
        };
        _cleanup_(dynamic_creds_done) DynamicCreds dynamic_creds = {};
        _cleanup_(exec_runtime_clear) ExecRuntime runtime = {
                .ephemeral_storage_socket = EBADF_PAIR,
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };
        int exit_status = EXIT_SUCCESS, r;

        exec_context_init(&context);
        cgroup_context_init(&cgroup_context);

        /* We might be starting the journal itself, we'll be told by the caller what to do */
        log_set_prohibit_ipc(true);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        /* Now that we know the intended log target, allow IPC and open the final log target. */
        log_set_always_reopen_console(true);
        log_set_prohibit_ipc(false);
        log_open();

        /* Clear ambient capabilities, so services do not inherit them implicitly. Dropping them does
         * not affect the permitted and effective sets which are important for the executor itself to
         * operate. */
        r = capability_ambient_set_apply(0, /* also_inherit= */ false);
        if (r < 0)
                log_warning_errno(r, "Failed to clear ambient capabilities, ignoring: %m");

        /* This call would collect all passed fds and enable CLOEXEC. We'll unset it in exec_invoke (flag_fds)
         * for fds that shall be passed to the child.
         * The serialization fd is set to CLOEXEC in parse_argv, so it's also filtered. */
        r = fdset_new_fill(/* filter_cloexec= */ 0, &fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to create fd set: %m");

        /* Initialize lazily. SMACK is just a few operations, but the SELinux is very slow as it requires
         * loading the entire database in memory, so we will do it lazily only if it is actually needed, to
         * avoid wasting 2ms-10ms for each sd-executor that gets spawned. */
        r = mac_init_lazy();
        if (r < 0)
                return log_error_errno(r, "Failed to initialize MAC layer: %m");

        r = exec_deserialize_invocation(arg_serialization,
                                        fdset,
                                        &context,
                                        &command,
                                        &params,
                                        &runtime,
                                        &cgroup_context);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize: %m");

        LOG_CONTEXT_PUSH_EXEC(&context, &params);

        arg_serialization = safe_fclose(arg_serialization);
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

                log_struct_errno(LOG_ERR, r,
                                 LOG_MESSAGE_ID(SD_MESSAGE_SPAWN_FAILED_STR),
                                 LOG_EXEC_MESSAGE(&params, "Failed at step %s spawning %s: %m",
                                                  status, command.path),
                                 LOG_ITEM("EXECUTABLE=%s", command.path));
        } else
                /* r == 0: 'skip' is chosen in the confirm spawn prompt
                 * r > 0:  expected/ignored failure, do not log at error level */
                assert((r == 0) == (exit_status == EXIT_SUCCESS));

        return exit_status;
}

int main(int argc, char *argv[]) {
        int r;

        /* We use safe_fork() for spawning sd-pam helper process, which internally calls rename_process().
         * As the last step of renaming, all saved argvs are memzero()-ed. Hence, we need to save the argv
         * first to prevent showing "intense" cmdline. See #30352. */
        save_argc_argv(argc, argv);

        r = run(argc, argv);

        mac_selinux_finish();
        static_destruct();

        return r < 0 ? EXIT_FAILURE : r;
}
