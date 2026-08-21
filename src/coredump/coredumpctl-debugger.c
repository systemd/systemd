/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-journal.h"

#include "coredumpctl.h"
#include "coredumpctl-core.h"
#include "coredumpctl-debugger.h"
#include "coredumpctl-info.h"
#include "coredumpctl-journal.h"
#include "coredumpctl-util.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"

int verb_run_debug(int argc, char *argv[], uintptr_t _data, void *userdata) {
        static const struct sigaction sa = {
                .sa_sigaction = sigterm_process_group_handler,
                .sa_flags = SA_SIGINFO,
        };

        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *exe = NULL;
        _cleanup_strv_free_ char **debugger_call = NULL;
        const char *data, *fork_name;
        size_t len;
        int r;

        if (!arg_debugger) {
                char *env_debugger;

                env_debugger = getenv("SYSTEMD_DEBUGGER");
                if (env_debugger)
                        arg_debugger = env_debugger;
                else
                        arg_debugger = "gdb";
        }

        r = strv_extend(&debugger_call, arg_debugger);
        if (r < 0)
                return log_oom();

        r = strv_extend_strv(&debugger_call, arg_debugger_args, false);
        if (r < 0)
                return log_oom();

        if (arg_field)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --field/-F only makes sense with list");

        r = acquire_journal(&j, strv_skip(argv, 1));
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        if (!arg_quiet) {
                print_entry(stdout, j, /* need_space= */ false, /* table= */ NULL);
                fputs("\n", stdout);
        }

        r = sd_journal_get_data(j, "COREDUMP_EXE", (const void**) &data, &len);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve COREDUMP_EXE field: %m");

        assert(len > STRLEN("COREDUMP_EXE="));
        data += STRLEN("COREDUMP_EXE=");
        len -= STRLEN("COREDUMP_EXE=");

        exe = strndup(data, len);
        if (!exe)
                return log_oom();

        if (endswith(exe, " (deleted)"))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Binary already deleted.");

        if (!path_is_absolute(exe))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Binary is not an absolute path.");

        r = resolve_filename(arg_root, &exe);
        if (r < 0)
                return r;

        _cleanup_(unlink_and_freep) char *temp = NULL;
        _cleanup_free_ char *path = NULL;
        r = acquire_core(j, /* fd= */ -EBADF, &temp, &path);
        if (r < 0)
                return r;

        assert(!path == !!temp);
        r = strv_extend_many(&debugger_call, exe, "-c", path ?: temp);
        if (r < 0)
                return log_oom();

        if (arg_root) {
                if (streq(arg_debugger, "gdb")) {
                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("set sysroot ", arg_root);

                        r = strv_extend_many(&debugger_call, "-iex", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                } else if (streq(arg_debugger, "lldb")) {
                        const char *sysroot_cmd;
                        sysroot_cmd = strjoina("platform select --sysroot ", arg_root, " host");

                        r = strv_extend_many(&debugger_call, "-O", sysroot_cmd);
                        if (r < 0)
                                return log_oom();
                }
        }

        /* Don't interfere with gdb and its handling of SIGINT. */
        (void) ignore_signals(SIGINT);
        (void) sigaction(SIGTERM, &sa, NULL);

        fork_name = strjoina("(", debugger_call[0], ")");

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        fork_name,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG|FORK_FLUSH_STDIO,
                        &pidref);
        if (r < 0)
                goto finish;
        if (r == 0) {
                execvp(debugger_call[0], debugger_call);
                log_open();
                log_error_errno(errno, "Failed to invoke %s: %m", debugger_call[0]);
                _exit(EXIT_FAILURE);
        }

        r = pidref_wait_for_terminate_and_check(debugger_call[0], &pidref, WAIT_LOG_ABNORMAL);

finish:
        (void) default_signals(SIGINT, SIGTERM);

        return r;
}
