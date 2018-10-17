/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "def.h"
#include "env-util.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "macro.h"
#include "process-util.h"
#include "serialize.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "util.h"

/* Put this test here for a lack of better place */
assert_cc(EAGAIN == EWOULDBLOCK);

static int do_spawn(const char *path, char *argv[], int stdout_fd, pid_t *pid) {

        pid_t _pid;
        int r;

        if (null_or_empty_path(path)) {
                log_debug("%s is empty (a mask).", path);
                return 0;
        }

        r = safe_fork("(direxec)", FORK_DEATHSIG|FORK_LOG, &_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                char *_argv[2];

                if (stdout_fd >= 0) {
                        r = rearrange_stdio(STDIN_FILENO, stdout_fd, STDERR_FILENO);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
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

        *pid = _pid;
        return 1;
}

static int do_execute(
                char **directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                int output_fd,
                char *argv[],
                char *envp[]) {

        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        _cleanup_strv_free_ char **paths = NULL;
        char **path, **e;
        int r;

        /* We fork this all off from a child process so that we can somewhat cleanly make
         * use of SIGALRM to set a time limit.
         *
         * If callbacks is nonnull, execution is serial. Otherwise, we default to parallel.
         */

        r = conf_files_list_strv(&paths, NULL, NULL, CONF_FILES_EXECUTABLE|CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char* const*) directories);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate executables: %m");

        if (!callbacks) {
                pids = hashmap_new(NULL);
                if (!pids)
                        return log_oom();
        }

        /* Abort execution of this process after the timout. We simply rely on SIGALRM as
         * default action terminating the process, and turn on alarm(). */

        if (timeout != USEC_INFINITY)
                alarm(DIV_ROUND_UP(timeout, USEC_PER_SEC));

        STRV_FOREACH(e, envp)
                if (putenv(*e) != 0)
                        return log_error_errno(errno, "Failed to set environment variable: %m");

        STRV_FOREACH(path, paths) {
                _cleanup_free_ char *t = NULL;
                _cleanup_close_ int fd = -1;
                pid_t pid;

                t = strdup(*path);
                if (!t)
                        return log_oom();

                if (callbacks) {
                        fd = open_serialization_fd(basename(*path));
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to open serialization file: %m");
                }

                r = do_spawn(t, argv, fd, &pid);
                if (r <= 0)
                        continue;

                if (pids) {
                        r = hashmap_put(pids, PID_TO_PTR(pid), t);
                        if (r < 0)
                                return log_oom();
                        t = NULL;
                } else {
                        r = wait_for_terminate_and_check(t, pid, WAIT_LOG);
                        if (r < 0)
                                continue;

                        if (lseek(fd, 0, SEEK_SET) < 0)
                                return log_error_errno(errno, "Failed to seek on serialization fd: %m");

                        r = callbacks[STDOUT_GENERATE](fd, callback_args[STDOUT_GENERATE]);
                        fd = -1;
                        if (r < 0)
                                return log_error_errno(r, "Failed to process output from %s: %m", *path);
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

                pid = PTR_TO_PID(hashmap_first_key(pids));
                assert(pid > 0);

                t = hashmap_remove(pids, PID_TO_PTR(pid));
                assert(t);

                (void) wait_for_terminate_and_check(t, pid, WAIT_LOG);
        }

        return 0;
}

int execute_directories(
                const char* const* directories,
                usec_t timeout,
                gather_stdout_callback_t const callbacks[_STDOUT_CONSUME_MAX],
                void* const callback_args[_STDOUT_CONSUME_MAX],
                char *argv[],
                char *envp[]) {

        char **dirs = (char**) directories;
        _cleanup_close_ int fd = -1;
        char *name;
        int r;

        assert(!strv_isempty(dirs));

        name = basename(dirs[0]);
        assert(!isempty(name));

        if (callbacks) {
                assert(callback_args);
                assert(callbacks[STDOUT_GENERATE]);
                assert(callbacks[STDOUT_COLLECT]);
                assert(callbacks[STDOUT_CONSUME]);

                fd = open_serialization_fd(name);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to open serialization file: %m");
        }

        /* Executes all binaries in the directories serially or in parallel and waits for
         * them to finish. Optionally a timeout is applied. If a file with the same name
         * exists in more than one directory, the earliest one wins. */

        r = safe_fork("(sd-executor)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG|FORK_WAIT, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                r = do_execute(dirs, timeout, callbacks, callback_args, fd, argv, envp);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        if (!callbacks)
                return 0;

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to rewind serialization fd: %m");

        r = callbacks[STDOUT_CONSUME](fd, callback_args[STDOUT_CONSUME]);
        fd = -1;
        if (r < 0)
                return log_error_errno(r, "Failed to parse returned data: %m");
        return 0;
}

static int gather_environment_generate(int fd, void *arg) {
        char ***env = arg, **x, **y;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **new = NULL;
        int r;

        /* Read a series of VAR=value assignments from fd, use them to update the list of
         * variables in env. Also update the exported environment.
         *
         * fd is always consumed, even on error.
         */

        assert(env);

        f = fdopen(fd, "r");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        r = load_env_file_pairs(f, NULL, NULL, &new);
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(x, y, new) {
                char *p;

                if (!env_name_is_valid(*x)) {
                        log_warning("Invalid variable assignment \"%s=...\", ignoring.", *x);
                        continue;
                }

                p = strjoin(*x, "=", *y);
                if (!p)
                        return -ENOMEM;

                r = strv_env_replace(env, p);
                if (r < 0)
                        return r;

                if (setenv(*x, *y, true) < 0)
                        return -errno;
        }

        return r;
}

static int gather_environment_collect(int fd, void *arg) {
        _cleanup_fclose_ FILE *f = NULL;
        char ***env = arg;
        int r;

        /* Write out a series of env=cescape(VAR=value) assignments to fd. */

        assert(env);

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
        _cleanup_fclose_ FILE *f = NULL;
        char ***env = arg;
        int r = 0;

        /* Read a series of env=cescape(VAR=value) assignments from fd into env. */

        assert(env);

        f = fdopen(fd, "re");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *v;
                int k;

                k = read_line(f, LONG_LINE_MAX, &line);
                if (k < 0)
                        return k;
                if (k == 0)
                        break;

                v = startswith(line, "env=");
                if (!v) {
                        log_debug("Serialization line \"%s\" unexpectedly didn't start with \"env=\".", line);
                        if (r == 0)
                                r = -EINVAL;

                        continue;
                }

                k = deserialize_environment(v, env);
                if (k < 0) {
                        log_debug_errno(k, "Invalid serialization line \"%s\": %m", line);

                        if (r == 0)
                                r = k;
                }
        }

        return r;
}

const gather_stdout_callback_t gather_environment[] = {
        gather_environment_generate,
        gather_environment_collect,
        gather_environment_consume,
};
