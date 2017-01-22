/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dirent.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "exec-util.h"
#include "hashmap.h"
#include "macro.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

/* Put this test here for a lack of better place */
assert_cc(EAGAIN == EWOULDBLOCK);

static int do_spawn(const char *path, char *argv[], pid_t *pid) {
        pid_t _pid;

        if (null_or_empty_path(path)) {
                log_debug("%s is empty (a mask).", path);
                return 0;
        }

        _pid = fork();
        if (_pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");
        if (_pid == 0) {
                char *_argv[2];

                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

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

        log_debug("Spawned %s as " PID_FMT ".", path, _pid);
        *pid = _pid;
        return 1;
}

static int do_execute(char **directories, usec_t timeout, char *argv[]) {
        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        _cleanup_strv_free_ char **paths = NULL;
        char **path;
        int r;

        /* We fork this all off from a child process so that we can
         * somewhat cleanly make use of SIGALRM to set a time limit */

        (void) reset_all_signal_handlers();
        (void) reset_signal_mask();

        assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

        r = conf_files_list_strv(&paths, NULL, NULL, (const char* const*) directories);
        if (r < 0)
                return r;

        pids = hashmap_new(NULL);
        if (!pids)
                return log_oom();

        STRV_FOREACH(path, paths) {
                _cleanup_free_ char *t = NULL;
                pid_t pid;

                t = strdup(*path);
                if (!t)
                        return log_oom();

                r = do_spawn(t, argv, &pid);
                if (r <= 0)
                        continue;

                r = hashmap_put(pids, PID_TO_PTR(pid), t);
                if (r < 0)
                        return log_oom();

                t = NULL;
        }

        /* Abort execution of this process after the timout. We simply
         * rely on SIGALRM as default action terminating the process,
         * and turn on alarm(). */

        if (timeout != USEC_INFINITY)
                alarm((timeout + USEC_PER_SEC - 1) / USEC_PER_SEC);

        while (!hashmap_isempty(pids)) {
                _cleanup_free_ char *t = NULL;
                pid_t pid;

                pid = PTR_TO_PID(hashmap_first_key(pids));
                assert(pid > 0);

                t = hashmap_remove(pids, PID_TO_PTR(pid));
                assert(t);

                wait_for_terminate_and_warn(t, pid, true);
        }

        return 0;
}

void execute_directories(const char* const* directories, usec_t timeout, char *argv[]) {
        pid_t executor_pid;
        int r;
        char *name;
        char **dirs = (char**) directories;

        assert(!strv_isempty(dirs));

        name = basename(dirs[0]);
        assert(!isempty(name));

        /* Executes all binaries in the directories in parallel and waits
         * for them to finish. Optionally a timeout is applied. If a file
         * with the same name exists in more than one directory, the
         * earliest one wins. */

        executor_pid = fork();
        if (executor_pid < 0) {
                log_error_errno(errno, "Failed to fork: %m");
                return;

        } else if (executor_pid == 0) {
                r = do_execute(dirs, timeout, argv);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        wait_for_terminate_and_warn(name, executor_pid, true);
}
