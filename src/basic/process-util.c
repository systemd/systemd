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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "ioprio.h"
#include "log.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

int get_process_state(pid_t pid) {
        const char *p;
        char state;
        int r;
        _cleanup_free_ char *line = NULL;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "stat");

        r = read_one_line_file(p, &line);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " %c", &state) != 1)
                return -EIO;

        return (unsigned char) state;
}

int get_process_comm(pid_t pid, char **name) {
        const char *p;
        int r;

        assert(name);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "comm");

        r = read_one_line_file(p, name);
        if (r == -ENOENT)
                return -ESRCH;

        return r;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        char *r = NULL, *k;
        const char *p;
        int c;

        assert(line);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "cmdline");

        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        if (max_length == 0) {
                size_t len = 0, allocated = 0;

                while ((c = getc(f)) != EOF) {

                        if (!GREEDY_REALLOC(r, allocated, len+2)) {
                                free(r);
                                return -ENOMEM;
                        }

                        r[len++] = isprint(c) ? c : ' ';
                }

                if (len > 0)
                        r[len-1] = 0;

        } else {
                bool space = false;
                size_t left;

                r = new(char, max_length);
                if (!r)
                        return -ENOMEM;

                k = r;
                left = max_length;
                while ((c = getc(f)) != EOF) {

                        if (isprint(c)) {
                                if (space) {
                                        if (left <= 4)
                                                break;

                                        *(k++) = ' ';
                                        left--;
                                        space = false;
                                }

                                if (left <= 4)
                                        break;

                                *(k++) = (char) c;
                                left--;
                        }  else
                                space = true;
                }

                if (left <= 4) {
                        size_t n = MIN(left-1, 3U);
                        memcpy(k, "...", n);
                        k[n] = 0;
                } else
                        *k = 0;
        }

        /* Kernel threads have no argv[] */
        if (isempty(r)) {
                _cleanup_free_ char *t = NULL;
                int h;

                free(r);

                if (!comm_fallback)
                        return -ENOENT;

                h = get_process_comm(pid, &t);
                if (h < 0)
                        return h;

                r = strjoin("[", t, "]", NULL);
                if (!r)
                        return -ENOMEM;
        }

        *line = r;
        return 0;
}

void rename_process(const char name[8]) {
        assert(name);

        /* This is a like a poor man's setproctitle(). It changes the
         * comm field, argv[0], and also the glibc's internally used
         * name of the process. For the first one a limit of 16 chars
         * applies, to the second one usually one of 10 (i.e. length
         * of "/sbin/init"), to the third one one of 7 (i.e. length of
         * "systemd"). If you pass a longer string it will be
         * truncated */

        prctl(PR_SET_NAME, name);

        if (program_invocation_name)
                strncpy(program_invocation_name, name, strlen(program_invocation_name));

        if (saved_argc > 0) {
                int i;

                if (saved_argv[0])
                        strncpy(saved_argv[0], name, strlen(saved_argv[0]));

                for (i = 1; i < saved_argc; i++) {
                        if (!saved_argv[i])
                                break;

                        memzero(saved_argv[i], strlen(saved_argv[i]));
                }
        }
}

int is_kernel_thread(pid_t pid) {
        const char *p;
        size_t count;
        char c;
        bool eof;
        FILE *f;

        if (pid == 0 || pid == 1) /* pid 1, and we ourselves certainly aren't a kernel thread */
                return 0;

        assert(pid > 1);

        p = procfs_file_alloca(pid, "cmdline");
        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        count = fread(&c, 1, 1, f);
        eof = feof(f);
        fclose(f);

        /* Kernel threads have an empty cmdline */

        if (count <= 0)
                return eof ? 1 : -errno;

        return 0;
}

int get_process_capeff(pid_t pid, char **capeff) {
        const char *p;
        int r;

        assert(capeff);
        assert(pid >= 0);

        p = procfs_file_alloca(pid, "status");

        r = get_proc_field(p, "CapEff", WHITESPACE, capeff);
        if (r == -ENOENT)
                return -ESRCH;

        return r;
}

static int get_process_link_contents(const char *proc_file, char **name) {
        int r;

        assert(proc_file);
        assert(name);

        r = readlink_malloc(proc_file, name);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        return 0;
}

int get_process_exe(pid_t pid, char **name) {
        const char *p;
        char *d;
        int r;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "exe");
        r = get_process_link_contents(p, name);
        if (r < 0)
                return r;

        d = endswith(*name, " (deleted)");
        if (d)
                *d = '\0';

        return 0;
}

static int get_process_id(pid_t pid, const char *field, uid_t *uid) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        const char *p;

        assert(field);
        assert(uid);

        if (pid == 0)
                return getuid();

        p = procfs_file_alloca(pid, "status");
        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        FOREACH_LINE(line, f, return -errno) {
                char *l;

                l = strstrip(line);

                if (startswith(l, field)) {
                        l += strlen(field);
                        l += strspn(l, WHITESPACE);

                        l[strcspn(l, WHITESPACE)] = 0;

                        return parse_uid(l, uid);
                }
        }

        return -EIO;
}

int get_process_uid(pid_t pid, uid_t *uid) {
        return get_process_id(pid, "Uid:", uid);
}

int get_process_gid(pid_t pid, gid_t *gid) {
        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        return get_process_id(pid, "Gid:", gid);
}

int get_process_cwd(pid_t pid, char **cwd) {
        const char *p;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "cwd");

        return get_process_link_contents(p, cwd);
}

int get_process_root(pid_t pid, char **root) {
        const char *p;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "root");

        return get_process_link_contents(p, root);
}

int get_process_environ(pid_t pid, char **env) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *outcome = NULL;
        int c;
        const char *p;
        size_t allocated = 0, sz = 0;

        assert(pid >= 0);
        assert(env);

        p = procfs_file_alloca(pid, "environ");

        f = fopen(p, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        while ((c = fgetc(f)) != EOF) {
                if (!GREEDY_REALLOC(outcome, allocated, sz + 5))
                        return -ENOMEM;

                if (c == '\0')
                        outcome[sz++] = '\n';
                else
                        sz += cescape_char(c, outcome + sz);
        }

        if (!outcome) {
                outcome = strdup("");
                if (!outcome)
                        return -ENOMEM;
        } else
                outcome[sz] = '\0';

        *env = outcome;
        outcome = NULL;

        return 0;
}

int get_process_ppid(pid_t pid, pid_t *_ppid) {
        int r;
        _cleanup_free_ char *line = NULL;
        long unsigned ppid;
        const char *p;

        assert(pid >= 0);
        assert(_ppid);

        if (pid == 0) {
                *_ppid = getppid();
                return 0;
        }

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* Let's skip the pid and comm fields. The latter is enclosed
         * in () but does not escape any () in its value, so let's
         * skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%lu ", /* ppid */
                   &ppid) != 1)
                return -EIO;

        if ((long unsigned) (pid_t) ppid != ppid)
                return -ERANGE;

        *_ppid = (pid_t) ppid;

        return 0;
}

int wait_for_terminate(pid_t pid, siginfo_t *status) {
        siginfo_t dummy;

        assert(pid >= 1);

        if (!status)
                status = &dummy;

        for (;;) {
                zero(*status);

                if (waitid(P_PID, pid, status, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                return 0;
        }
}

/*
 * Return values:
 * < 0 : wait_for_terminate() failed to get the state of the
 *       process, the process was terminated by a signal, or
 *       failed for an unknown reason.
 * >=0 : The process terminated normally, and its exit code is
 *       returned.
 *
 * That is, success is indicated by a return value of zero, and an
 * error is indicated by a non-zero value.
 *
 * A warning is emitted if the process terminates abnormally,
 * and also if it returns non-zero unless check_exit_code is true.
 */
int wait_for_terminate_and_warn(const char *name, pid_t pid, bool check_exit_code) {
        int r;
        siginfo_t status;

        assert(name);
        assert(pid > 1);

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return log_warning_errno(r, "Failed to wait for %s: %m", name);

        if (status.si_code == CLD_EXITED) {
                if (status.si_status != 0)
                        log_full(check_exit_code ? LOG_WARNING : LOG_DEBUG,
                                 "%s failed with error code %i.", name, status.si_status);
                else
                        log_debug("%s succeeded.", name);

                return status.si_status;
        } else if (status.si_code == CLD_KILLED ||
                   status.si_code == CLD_DUMPED) {

                log_warning("%s terminated by signal %s.", name, signal_to_string(status.si_status));
                return -EPROTO;
        }

        log_warning("%s failed due to unknown reason.", name);
        return -EPROTO;
}

void sigkill_wait(pid_t *pid) {
        if (!pid)
                return;
        if (*pid <= 1)
                return;

        if (kill(*pid, SIGKILL) > 0)
                (void) wait_for_terminate(*pid, NULL);
}

int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = kill(pid, sig) < 0 ? -errno : 0;

        if (r >= 0)
                kill(pid, SIGCONT);

        return r;
}

int getenv_for_pid(pid_t pid, const char *field, char **_value) {
        _cleanup_fclose_ FILE *f = NULL;
        char *value = NULL;
        int r;
        bool done = false;
        size_t l;
        const char *path;

        assert(pid >= 0);
        assert(field);
        assert(_value);

        path = procfs_file_alloca(pid, "environ");

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return -ESRCH;
                return -errno;
        }

        l = strlen(field);
        r = 0;

        do {
                char line[LINE_MAX];
                unsigned i;

                for (i = 0; i < sizeof(line)-1; i++) {
                        int c;

                        c = getc(f);
                        if (_unlikely_(c == EOF)) {
                                done = true;
                                break;
                        } else if (c == 0)
                                break;

                        line[i] = c;
                }
                line[i] = 0;

                if (memcmp(line, field, l) == 0 && line[l] == '=') {
                        value = strdup(line + l + 1);
                        if (!value)
                                return -ENOMEM;

                        r = 1;
                        break;
                }

        } while (!done);

        *_value = value;
        return r;
}

bool pid_is_unwaited(pid_t pid) {
        /* Checks whether a PID is still valid at all, including a zombie */

        if (pid < 0)
                return false;

        if (pid <= 1) /* If we or PID 1 would be dead and have been waited for, this code would not be running */
                return true;

        if (kill(pid, 0) >= 0)
                return true;

        return errno != ESRCH;
}

bool pid_is_alive(pid_t pid) {
        int r;

        /* Checks whether a PID is still valid and not a zombie */

        if (pid < 0)
                return false;

        if (pid <= 1) /* If we or PID 1 would be a zombie, this code would not be running */
                return true;

        r = get_process_state(pid);
        if (r == -ESRCH || r == 'Z')
                return false;

        return true;
}

bool is_main_thread(void) {
        static thread_local int cached = 0;

        if (_unlikely_(cached == 0))
                cached = getpid() == gettid() ? 1 : -1;

        return cached > 0;
}

noreturn void freeze(void) {

        /* Make sure nobody waits for us on a socket anymore */
        close_all_fds(NULL, 0);

        sync();

        for (;;)
                pause();
}

bool oom_score_adjust_is_valid(int oa) {
        return oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX;
}

unsigned long personality_from_string(const char *p) {

        /* Parse a personality specifier. We introduce our own
         * identifiers that indicate specific ABIs, rather than just
         * hints regarding the register size, since we want to keep
         * things open for multiple locally supported ABIs for the
         * same register size. We try to reuse the ABI identifiers
         * used by libseccomp. */

#if defined(__x86_64__)

        if (streq(p, "x86"))
                return PER_LINUX32;

        if (streq(p, "x86-64"))
                return PER_LINUX;

#elif defined(__i386__)

        if (streq(p, "x86"))
                return PER_LINUX;

#elif defined(__s390x__)

        if (streq(p, "s390"))
                return PER_LINUX32;

        if (streq(p, "s390x"))
                return PER_LINUX;

#elif defined(__s390__)

        if (streq(p, "s390"))
                return PER_LINUX;
#endif

        return PERSONALITY_INVALID;
}

const char* personality_to_string(unsigned long p) {

#if defined(__x86_64__)

        if (p == PER_LINUX32)
                return "x86";

        if (p == PER_LINUX)
                return "x86-64";

#elif defined(__i386__)

        if (p == PER_LINUX)
                return "x86";

#elif defined(__s390x__)

        if (p == PER_LINUX)
                return "s390x";

        if (p == PER_LINUX32)
                return "s390";

#elif defined(__s390__)

        if (p == PER_LINUX)
                return "s390";

#endif

        return NULL;
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ioprio_class, int, INT_MAX);

static const char *const sigchld_code_table[] = {
        [CLD_EXITED] = "exited",
        [CLD_KILLED] = "killed",
        [CLD_DUMPED] = "dumped",
        [CLD_TRAPPED] = "trapped",
        [CLD_STOPPED] = "stopped",
        [CLD_CONTINUED] = "continued",
};

DEFINE_STRING_TABLE_LOOKUP(sigchld_code, int);

static const char* const sched_policy_table[] = {
        [SCHED_OTHER] = "other",
        [SCHED_BATCH] = "batch",
        [SCHED_IDLE] = "idle",
        [SCHED_FIFO] = "fifo",
        [SCHED_RR] = "rr"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(sched_policy, int, INT_MAX);
