/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dirent.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "alloc-util.h"
#include "bitfield.h"
#include "conf-files.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "macro.h"
#include "missing_syscall.h"
#include "path-util.h"
#include "process-util.h"
#include "serialize.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"

#define EXIT_SKIP_REMAINING 77

/* Put this test here for a lack of better place */
assert_cc(EAGAIN == EWOULDBLOCK);

static int do_spawn(
                const char *path,
                char *argv[],
                int stdout_fd,
                bool set_systemd_exec_pid,
                pid_t *ret_pid) {

        int r;

        assert(path);
        assert(ret_pid);

        if (null_or_empty_path(path) > 0) {
                log_debug("%s is masked, skipping.", path);
                return 0;
        }

        pid_t pid;
        r = safe_fork_full(
                        "(exec-inner)",
                        (const int[]) { STDIN_FILENO, stdout_fd < 0 ? STDOUT_FILENO : stdout_fd, STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO|FORK_CLOSE_ALL_FDS,
                        &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                char *_argv[2];

                if (set_systemd_exec_pid) {
                        r = setenv_systemd_exec_pid(false);
                        if (r < 0)
                                log_warning_errno(r, "Failed to set $SYSTEMD_EXEC_PID, ignoring: %m");
                }

                if (!argv) {
                        _argv[0] = (char*) path;
                        _argv[1] = NULL;
                        argv = _argv;
                } else
                        argv[0] = (char*) path;

                execv(path, argv);
                log_error_errno(errno, "Failed to execute %s: %m", path);
                _exit(EXIT_FAILURE);
        }

        *ret_pid = pid;
        return 1;
}

static int do_execute(
                char * const *paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void * const callback_args[_STDOUT_CONSUME_MAX],
                int output_fd,
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_hashmap_free_ Hashmap *pids = NULL;
        bool parallel_execution;
        int r;

        /* We fork this all off from a child process so that we can somewhat cleanly make use of SIGALRM
         * to set a time limit.
         *
         * We attempt to perform parallel execution if configured by the user, however if `callbacks` is nonnull,
         * execution must be serial.
         */

        assert(!strv_isempty(paths));

        parallel_execution = FLAGS_SET(flags, EXEC_DIR_PARALLEL) && !callbacks;

        /* Abort execution of this process after the timeout. We simply rely on SIGALRM as
         * default action terminating the process, and turn on alarm(). */

        if (timeout != USEC_INFINITY)
                alarm(DIV_ROUND_UP(timeout, USEC_PER_SEC));

        STRV_FOREACH(e, envp)
                if (putenv(*e) != 0)
                        return log_error_errno(errno, "Failed to set environment variable: %m");

        STRV_FOREACH(path, paths) {
                _cleanup_free_ char *t = NULL;
                _cleanup_close_ int fd = -EBADF;
                pid_t pid;

                t = path_join(root, *path);
                if (!t)
                        return log_oom();

                if (callbacks) {
                        _cleanup_free_ char *bn = NULL;

                        r = path_extract_filename(*path, &bn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from path '%s': %m", *path);

                        fd = open_serialization_fd(bn);
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to open serialization file: %m");
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *args = NULL;
                        if (argv)
                                args = quote_command_line(strv_skip(argv, 1), SHELL_ESCAPE_EMPTY);

                        log_debug("About to execute %s%s%s", t, argv ? " " : "", argv ? strnull(args) : "");
                }

                if (FLAGS_SET(flags, EXEC_DIR_WARN_WORLD_WRITABLE)) {
                        struct stat st;

                        r = stat(t, &st);
                        if (r < 0)
                                log_warning_errno(errno, "Failed to stat '%s', ignoring: %m", t);
                        else if (S_ISREG(st.st_mode) && (st.st_mode & 0002))
                                log_warning("'%s' is marked world-writable, which is a security risk as it "
                                            "is executed with privileges. Please remove world writability "
                                            "permission bits. Proceeding anyway.", t);
                }

                r = do_spawn(t, argv, fd, FLAGS_SET(flags, EXEC_DIR_SET_SYSTEMD_EXEC_PID), &pid);
                if (r <= 0)
                        continue;

                if (parallel_execution) {
                        r = hashmap_ensure_put(&pids, &trivial_hash_ops_value_free, PID_TO_PTR(pid), t);
                        if (r < 0)
                                return log_oom();
                        t = NULL;
                } else {
                        bool skip_remaining = false;

                        r = wait_for_terminate_and_check(t, pid, WAIT_LOG_ABNORMAL);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                if (FLAGS_SET(flags, EXEC_DIR_SKIP_REMAINING) && r == EXIT_SKIP_REMAINING) {
                                        log_info("%s succeeded with exit status %i, not executing remaining executables.", *path, r);
                                        skip_remaining = true;
                                } else if (FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS))
                                        log_warning("%s failed with exit status %i, ignoring.", *path, r);
                                else {
                                        log_error("%s failed with exit status %i.", *path, r);
                                        return r;
                                }
                        }

                        if (callbacks) {
                                r = finish_serialization_fd(fd);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to finish serialization fd: %m");

                                r = callbacks[STDOUT_GENERATE](TAKE_FD(fd), callback_args[STDOUT_GENERATE]);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to process output from %s: %m", *path);
                        }

                        if (skip_remaining)
                                break;
                }
        }

        if (callbacks) {
                r = callbacks[STDOUT_COLLECT](output_fd, callback_args[STDOUT_COLLECT]);
                if (r < 0)
                        return log_error_errno(r, "Callback two failed: %m");
        }

        while (!hashmap_isempty(pids)) {
                _cleanup_free_ char *t = NULL;
                pid_t pid;
                void *p;

                t = ASSERT_PTR(hashmap_steal_first_key_and_value(pids, &p));
                pid = PTR_TO_PID(p);
                assert(pid > 0);

                r = wait_for_terminate_and_check(t, pid, WAIT_LOG);
                if (r < 0)
                        return r;
                if (!FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS) && r > 0)
                        return r;
        }

        return 0;
}

int execute_strv(
                const char *name,
                char * const *paths,
                const char *root,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void * const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_close_ int fd = -EBADF;
        pid_t executor_pid;
        int r;

        assert(!FLAGS_SET(flags, EXEC_DIR_PARALLEL | EXEC_DIR_SKIP_REMAINING));

        if (strv_isempty(paths))
                return 0;

        if (callbacks) {
                assert(name);
                assert(callbacks[STDOUT_GENERATE]);
                assert(callbacks[STDOUT_COLLECT]);
                assert(callbacks[STDOUT_CONSUME]);
                assert(callback_args);

                fd = open_serialization_fd(name);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open serialization file: %m");
        }

        /* Executes all binaries in the directories serially or in parallel and waits for
         * them to finish. Optionally a timeout is applied. If a file with the same name
         * exists in more than one directory, the earliest one wins. */

        r = safe_fork("(sd-exec-strv)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &executor_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                r = do_execute(paths, root, timeout, callbacks, callback_args, fd, argv, envp, flags);
                _exit(r < 0 ? EXIT_FAILURE : r);
        }

        r = wait_for_terminate_and_check("(sd-exec-strv)", executor_pid, 0);
        if (r < 0)
                return r;
        if (!FLAGS_SET(flags, EXEC_DIR_IGNORE_ERRORS) && r > 0)
                return r;

        if (!callbacks)
                return 0;

        r = finish_serialization_fd(fd);
        if (r < 0)
                return log_error_errno(r, "Failed to finish serialization fd: %m");

        r = callbacks[STDOUT_CONSUME](TAKE_FD(fd), callback_args[STDOUT_CONSUME]);
        if (r < 0)
                return log_error_errno(r, "Failed to parse returned data: %m");

        return 0;
}

int execute_directories(
                const char * const *directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void * const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[],
                ExecDirFlags flags) {

        _cleanup_strv_free_ char **paths = NULL;
        _cleanup_free_ char *name = NULL;
        int r;

        assert(!strv_isempty((char* const*) directories));

        r = conf_files_list_strv(&paths, NULL, NULL, CONF_FILES_EXECUTABLE|CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, directories);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate executables: %m");

        if (strv_isempty(paths)) {
                log_debug("No executables found.");
                return 0;
        }

        if (callbacks) {
                r = path_extract_filename(directories[0], &name);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from '%s': %m", directories[0]);
        }

        return execute_strv(name, paths, /* root = */ NULL, timeout, callbacks, callback_args, argv, envp, flags);
}

static int gather_environment_generate(int fd, void *arg) {
        char ***env = ASSERT_PTR(arg);
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **new = NULL;
        int r;

        /* Read a series of VAR=value assignments from fd, use them to update the list of variables in env.
         * Also update the exported environment.
         *
         * fd is always consumed, even on error.
         */

        assert(fd >= 0);

        f = fdopen(fd, "r");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        r = load_env_file_pairs(f, NULL, &new);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(x, y, new) {
                if (!env_name_is_valid(*x)) {
                        log_warning("Invalid variable assignment \"%s=...\", ignoring.", *x);
                        continue;
                }

                r = strv_env_assign(env, *x, *y);
                if (r < 0)
                        return r;

                if (setenv(*x, *y, /* overwrite = */ true) < 0)
                        return -errno;
        }

        return 0;
}

static int gather_environment_collect(int fd, void *arg) {
        char ***env = ASSERT_PTR(arg);
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Write out a series of env=cescape(VAR=value) assignments to fd. */

        assert(fd >= 0);

        f = fdopen(fd, "w");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        r = serialize_strv(f, "env", *env);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return r;

        return 0;
}

static int gather_environment_consume(int fd, void *arg) {
        char ***env = ASSERT_PTR(arg);
        _cleanup_fclose_ FILE *f = NULL;
        int r, ret = 0;

        /* Read a series of env=cescape(VAR=value) assignments from fd into env. */

        assert(fd >= 0);

        f = fdopen(fd, "r");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *v;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return ret;

                v = startswith(line, "env=");
                if (!v) {
                        RET_GATHER(ret, log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                                        "Serialization line unexpectedly didn't start with \"env=\", ignoring: %s",
                                                        line));
                        continue;
                }

                r = deserialize_environment(v, env);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to deserialize line \"%s\": %m", line));
        }
}

const gather_stdout_callback_t gather_environment[_STDOUT_CONSUME_MAX] = {
        gather_environment_generate,
        gather_environment_collect,
        gather_environment_consume,
};

int exec_command_flags_from_strv(char * const *ex_opts, ExecCommandFlags *ret) {
        ExecCommandFlags flags = 0;

        assert(ret);

        STRV_FOREACH(opt, ex_opts) {
                ExecCommandFlags fl = exec_command_flags_from_string(*opt);
                if (fl < 0)
                        return fl;

                flags |= fl;
        }

        *ret = flags;

        return 0;
}

int exec_command_flags_to_strv(ExecCommandFlags flags, char ***ret) {
        _cleanup_strv_free_ char **opts = NULL;
        int r;

        assert(flags >= 0);
        assert(ret);

        BIT_FOREACH(i, flags) {
                const char *s = exec_command_flags_to_string(1 << i);
                if (!s)
                        return -EINVAL;

                r = strv_extend(&opts, s);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(opts);

        return 0;
}

static const char* const exec_command_strings[] = {
        "ignore-failure", /* EXEC_COMMAND_IGNORE_FAILURE */
        "privileged",     /* EXEC_COMMAND_FULLY_PRIVILEGED */
        "no-setuid",      /* EXEC_COMMAND_NO_SETUID */
        "no-env-expand",  /* EXEC_COMMAND_NO_ENV_EXPAND */
};

assert_cc((1 << ELEMENTSOF(exec_command_strings)) - 1 == _EXEC_COMMAND_FLAGS_ALL);

const char* exec_command_flags_to_string(ExecCommandFlags i) {
        for (size_t idx = 0; idx < ELEMENTSOF(exec_command_strings); idx++)
                if (i == (1 << idx))
                        return exec_command_strings[idx];

        return NULL;
}

ExecCommandFlags exec_command_flags_from_string(const char *s) {
        ssize_t idx;

        if (streq(s, "ambient")) /* Compatibility with ambient hack, removed in v258, map to no bits set */
                return 0;

        idx = string_table_lookup(exec_command_strings, ELEMENTSOF(exec_command_strings), s);
        if (idx < 0)
                return _EXEC_COMMAND_FLAGS_INVALID;

        return 1 << idx;
}

int fexecve_or_execve(int executable_fd, const char *executable, char *const argv[], char *const envp[]) {
        /* Refuse invalid fds, regardless if fexecve() use is enabled or not */
        if (executable_fd < 0)
                return -EBADF;

        /* Block any attempts on exploiting Linux' liberal argv[] handling, i.e. CVE-2021-4034 and suchlike */
        if (isempty(executable) || strv_isempty(argv))
                return -EINVAL;

#if ENABLE_FEXECVE

        execveat(executable_fd, "", argv, envp, AT_EMPTY_PATH);

        if (IN_SET(errno, ENOSYS, ENOENT) || ERRNO_IS_PRIVILEGE(errno))
                /* Old kernel or a script or an overzealous seccomp filter? Let's fall back to execve().
                 *
                 * fexecve(3): "If fd refers to a script (i.e., it is an executable text file that names a
                 * script interpreter with a first line that begins with the characters #!) and the
                 * close-on-exec flag has been set for fd, then fexecve() fails with the error ENOENT. This
                 * error occurs because, by the time the script interpreter is executed, fd has already been
                 * closed because of the close-on-exec flag. Thus, the close-on-exec flag can't be set on fd
                 * if it refers to a script."
                 *
                 * Unfortunately, if we unset close-on-exec, the script will be executed just fine, but (at
                 * least in case of bash) the script name, $0, will be shown as /dev/fd/nnn, which breaks
                 * scripts which make use of $0. Thus, let's fall back to execve() in this case.
                 */
#endif
                execve(executable, argv, envp);
        return -errno;
}

int shall_fork_agent(void) {
        int r;

        /* Check if we have a controlling terminal. If not (ENXIO here), we aren't actually invoked
         * interactively on a terminal, hence fail. */
        r = get_ctty_devnr(0, NULL);
        if (r == -ENXIO)
                return false;
        if (r < 0)
                return r;

        if (!is_main_thread())
                return -EPERM;

        return true;
}

int _fork_agent(const char *name, const int except[], size_t n_except, pid_t *ret_pid, const char *path, ...) {
        int r;

        assert(path);

        /* Spawns a temporary TTY agent, making sure it goes away when we go away */

        r = safe_fork_full(name,
                           NULL,
                           (int*) except, /* safe_fork_full only changes except if you pass in FORK_PACK_FDS, which we don't */
                           n_except,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_RLIMIT_NOFILE_SAFE,
                           ret_pid);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* In the child: */

        bool stdin_is_tty = isatty_safe(STDIN_FILENO),
                stdout_is_tty = isatty_safe(STDOUT_FILENO),
                stderr_is_tty = isatty_safe(STDERR_FILENO);

        if (!stdin_is_tty || !stdout_is_tty || !stderr_is_tty) {
                int fd;

                /* Detach from stdin/stdout/stderr and reopen /dev/tty for them. This is important to ensure
                 * that when systemctl is started via popen() or a similar call that expects to read EOF we
                 * actually do generate EOF and not delay this indefinitely by keeping an unused copy of
                 * stdin around. */
                fd = open_terminal("/dev/tty", stdin_is_tty ? O_WRONLY : (stdout_is_tty && stderr_is_tty) ? O_RDONLY : O_RDWR);
                if (fd < 0) {
                        log_error_errno(fd, "Failed to open /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stdin_is_tty && dup2(fd, STDIN_FILENO) < 0) {
                        log_error_errno(errno, "Failed to dup2 /dev/tty to STDIN: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stdout_is_tty && dup2(fd, STDOUT_FILENO) < 0) {
                        log_error_errno(errno, "Failed to dup2 /dev/tty to STDOUT: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stderr_is_tty && dup2(fd, STDERR_FILENO) < 0) {
                        log_error_errno(errno, "Failed to dup2 /dev/tty to STDERR: %m");
                        _exit(EXIT_FAILURE);
                }

                fd = safe_close_above_stdio(fd);
        }

        /* Count arguments */
        char **l = strv_from_stdarg_alloca(path);
        execv(path, l);
        log_error_errno(errno, "Failed to execute %s: %m", path);
        _exit(EXIT_FAILURE);
}
