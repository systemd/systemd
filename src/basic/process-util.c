/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/oom.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "alloc-util.h"
#include "architecture.h"
#include "escape.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "ioprio.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing.h"
#include "namespace-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utf8.h"

/* The kernel limits userspace processes to TASK_COMM_LEN (16 bytes), but allows higher values for its own
 * workers, e.g. "kworker/u9:3-kcryptd/253:0". Let's pick a fixed smallish limit that will work for the kernel.
 */
#define COMM_MAX_LEN 128

static int get_process_state(pid_t pid) {
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

int get_process_comm(pid_t pid, char **ret) {
        _cleanup_free_ char *escaped = NULL, *comm = NULL;
        const char *p;
        int r;

        assert(ret);
        assert(pid >= 0);

        escaped = new(char, COMM_MAX_LEN);
        if (!escaped)
                return -ENOMEM;

        p = procfs_file_alloca(pid, "comm");

        r = read_one_line_file(p, &comm);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* Escape unprintable characters, just in case, but don't grow the string beyond the underlying size */
        cellescape(escaped, COMM_MAX_LEN, comm);

        *ret = TAKE_PTR(escaped);
        return 0;
}

int get_process_cmdline(pid_t pid, size_t max_columns, ProcessCmdlineFlags flags, char **line) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *t = NULL, *ans = NULL;
        const char *p;
        int r;
        size_t k;

        /* This is supposed to be a safety guard against runaway command lines. */
        size_t max_length = sc_arg_max();

        assert(line);
        assert(pid >= 0);

        /* Retrieves a process' command line. Replaces non-utf8 bytes by replacement character (�). If
         * max_columns is != -1 will return a string of the specified console width at most, abbreviated with
         * an ellipsis. If PROCESS_CMDLINE_COMM_FALLBACK is specified in flags and the process has no command
         * line set (the case for kernel threads), or has a command line that resolves to the empty string
         * will return the "comm" name of the process instead. This will use at most _SC_ARG_MAX bytes of
         * input data.
         *
         * Returns -ESRCH if the process doesn't exist, and -ENOENT if the process has no command line (and
         * comm_fallback is false). Returns 0 and sets *line otherwise. */

        p = procfs_file_alloca(pid, "cmdline");
        r = fopen_unlocked(p, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* We assume that each four-byte character uses one or two columns. If we ever check for combining
         * characters, this assumption will need to be adjusted. */
        if ((size_t) 4 * max_columns + 1 < max_columns)
                max_length = MIN(max_length, (size_t) 4 * max_columns + 1);

        t = new(char, max_length);
        if (!t)
                return -ENOMEM;

        k = fread(t, 1, max_length, f);
        if (k > 0) {
                /* Arguments are separated by NULs. Let's replace those with spaces. */
                for (size_t i = 0; i < k - 1; i++)
                        if (t[i] == '\0')
                                t[i] = ' ';

                t[k] = '\0'; /* Normally, t[k] is already NUL, so this is just a guard in case of short read */
        } else {
                /* We only treat getting nothing as an error. We *could* also get an error after reading some
                 * data, but we ignore that case, as such an error is rather unlikely and we prefer to get
                 * some data rather than none. */
                if (ferror(f))
                        return -errno;

                if (!(flags & PROCESS_CMDLINE_COMM_FALLBACK))
                        return -ENOENT;

                /* Kernel threads have no argv[] */
                _cleanup_free_ char *t2 = NULL;

                r = get_process_comm(pid, &t2);
                if (r < 0)
                        return r;

                mfree(t);
                t = strjoin("[", t2, "]");
                if (!t)
                        return -ENOMEM;
        }

        delete_trailing_chars(t, WHITESPACE);

        bool eight_bit = (flags & PROCESS_CMDLINE_USE_LOCALE) && !is_locale_utf8();

        ans = escape_non_printable_full(t, max_columns, eight_bit);
        if (!ans)
                return -ENOMEM;

        (void) str_realloc(&ans);
        *line = TAKE_PTR(ans);
        return 0;
}

int rename_process(const char name[]) {
        static size_t mm_size = 0;
        static char *mm = NULL;
        bool truncated = false;
        size_t l;

        /* This is a like a poor man's setproctitle(). It changes the comm field, argv[0], and also the glibc's
         * internally used name of the process. For the first one a limit of 16 chars applies; to the second one in
         * many cases one of 10 (i.e. length of "/sbin/init") — however if we have CAP_SYS_RESOURCES it is unbounded;
         * to the third one 7 (i.e. the length of "systemd". If you pass a longer string it will likely be
         * truncated.
         *
         * Returns 0 if a name was set but truncated, > 0 if it was set but not truncated. */

        if (isempty(name))
                return -EINVAL; /* let's not confuse users unnecessarily with an empty name */

        if (!is_main_thread())
                return -EPERM; /* Let's not allow setting the process name from other threads than the main one, as we
                                * cache things without locking, and we make assumptions that PR_SET_NAME sets the
                                * process name that isn't correct on any other threads */

        l = strlen(name);

        /* First step, change the comm field. The main thread's comm is identical to the process comm. This means we
         * can use PR_SET_NAME, which sets the thread name for the calling thread. */
        if (prctl(PR_SET_NAME, name) < 0)
                log_debug_errno(errno, "PR_SET_NAME failed: %m");
        if (l >= TASK_COMM_LEN) /* Linux userspace process names can be 15 chars at max */
                truncated = true;

        /* Second step, change glibc's ID of the process name. */
        if (program_invocation_name) {
                size_t k;

                k = strlen(program_invocation_name);
                strncpy(program_invocation_name, name, k);
                if (l > k)
                        truncated = true;
        }

        /* Third step, completely replace the argv[] array the kernel maintains for us. This requires privileges, but
         * has the advantage that the argv[] array is exactly what we want it to be, and not filled up with zeros at
         * the end. This is the best option for changing /proc/self/cmdline. */

        /* Let's not bother with this if we don't have euid == 0. Strictly speaking we should check for the
         * CAP_SYS_RESOURCE capability which is independent of the euid. In our own code the capability generally is
         * present only for euid == 0, hence let's use this as quick bypass check, to avoid calling mmap() if
         * PR_SET_MM_ARG_{START,END} fails with EPERM later on anyway. After all geteuid() is dead cheap to call, but
         * mmap() is not. */
        if (geteuid() != 0)
                log_debug("Skipping PR_SET_MM, as we don't have privileges.");
        else if (mm_size < l+1) {
                size_t nn_size;
                char *nn;

                nn_size = PAGE_ALIGN(l+1);
                nn = mmap(NULL, nn_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (nn == MAP_FAILED) {
                        log_debug_errno(errno, "mmap() failed: %m");
                        goto use_saved_argv;
                }

                strncpy(nn, name, nn_size);

                /* Now, let's tell the kernel about this new memory */
                if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0) {
                        /* HACK: prctl() API is kind of dumb on this point.  The existing end address may already be
                         * below the desired start address, in which case the kernel may have kicked this back due
                         * to a range-check failure (see linux/kernel/sys.c:validate_prctl_map() to see this in
                         * action).  The proper solution would be to have a prctl() API that could set both start+end
                         * simultaneously, or at least let us query the existing address to anticipate this condition
                         * and respond accordingly.  For now, we can only guess at the cause of this failure and try
                         * a workaround--which will briefly expand the arg space to something potentially huge before
                         * resizing it to what we want. */
                        log_debug_errno(errno, "PR_SET_MM_ARG_START failed, attempting PR_SET_MM_ARG_END hack: %m");

                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) nn + l + 1, 0, 0) < 0) {
                                log_debug_errno(errno, "PR_SET_MM_ARG_END hack failed, proceeding without: %m");
                                (void) munmap(nn, nn_size);
                                goto use_saved_argv;
                        }

                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0) {
                                log_debug_errno(errno, "PR_SET_MM_ARG_START still failed, proceeding without: %m");
                                goto use_saved_argv;
                        }
                } else {
                        /* And update the end pointer to the new end, too. If this fails, we don't really know what
                         * to do, it's pretty unlikely that we can rollback, hence we'll just accept the failure,
                         * and continue. */
                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) nn + l + 1, 0, 0) < 0)
                                log_debug_errno(errno, "PR_SET_MM_ARG_END failed, proceeding without: %m");
                }

                if (mm)
                        (void) munmap(mm, mm_size);

                mm = nn;
                mm_size = nn_size;
        } else {
                strncpy(mm, name, mm_size);

                /* Update the end pointer, continuing regardless of any failure. */
                if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) mm + l + 1, 0, 0) < 0)
                        log_debug_errno(errno, "PR_SET_MM_ARG_END failed, proceeding without: %m");
        }

use_saved_argv:
        /* Fourth step: in all cases we'll also update the original argv[], so that our own code gets it right too if
         * it still looks here */

        if (saved_argc > 0) {
                int i;

                if (saved_argv[0]) {
                        size_t k;

                        k = strlen(saved_argv[0]);
                        strncpy(saved_argv[0], name, k);
                        if (l > k)
                                truncated = true;
                }

                for (i = 1; i < saved_argc; i++) {
                        if (!saved_argv[i])
                                break;

                        memzero(saved_argv[i], strlen(saved_argv[i]));
                }
        }

        return !truncated;
}

int is_kernel_thread(pid_t pid) {
        _cleanup_free_ char *line = NULL;
        unsigned long long flags;
        size_t l, i;
        const char *p;
        char *q;
        int r;

        if (IN_SET(pid, 0, 1) || pid == getpid_cached()) /* pid 1, and we ourselves certainly aren't a kernel thread */
                return 0;
        if (!pid_is_valid(pid))
                return -EINVAL;

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* Skip past the comm field */
        q = strrchr(line, ')');
        if (!q)
                return -EINVAL;
        q++;

        /* Skip 6 fields to reach the flags field */
        for (i = 0; i < 6; i++) {
                l = strspn(q, WHITESPACE);
                if (l < 1)
                        return -EINVAL;
                q += l;

                l = strcspn(q, WHITESPACE);
                if (l < 1)
                        return -EINVAL;
                q += l;
        }

        /* Skip preceding whitespace */
        l = strspn(q, WHITESPACE);
        if (l < 1)
                return -EINVAL;
        q += l;

        /* Truncate the rest */
        l = strcspn(q, WHITESPACE);
        if (l < 1)
                return -EINVAL;
        q[l] = 0;

        r = safe_atollu(q, &flags);
        if (r < 0)
                return r;

        return !!(flags & PF_KTHREAD);
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
        const char *p;
        int r;

        assert(field);
        assert(uid);

        if (pid < 0)
                return -EINVAL;

        p = procfs_file_alloca(pid, "status");
        r = fopen_unlocked(p, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *l;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

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

        if (pid == 0 || pid == getpid_cached()) {
                *uid = getuid();
                return 0;
        }

        return get_process_id(pid, "Uid:", uid);
}

int get_process_gid(pid_t pid, gid_t *gid) {

        if (pid == 0 || pid == getpid_cached()) {
                *gid = getgid();
                return 0;
        }

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

#define ENVIRONMENT_BLOCK_MAX (5U*1024U*1024U)

int get_process_environ(pid_t pid, char **env) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *outcome = NULL;
        size_t allocated = 0, sz = 0;
        const char *p;
        int r;

        assert(pid >= 0);
        assert(env);

        p = procfs_file_alloca(pid, "environ");

        r = fopen_unlocked(p, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        for (;;) {
                char c;

                if (sz >= ENVIRONMENT_BLOCK_MAX)
                        return -ENOBUFS;

                if (!GREEDY_REALLOC(outcome, allocated, sz + 5))
                        return -ENOMEM;

                r = safe_fgetc(f, &c);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (c == '\0')
                        outcome[sz++] = '\n';
                else
                        sz += cescape_char(c, outcome + sz);
        }

        outcome[sz] = '\0';
        *env = TAKE_PTR(outcome);

        return 0;
}

int get_process_ppid(pid_t pid, pid_t *_ppid) {
        int r;
        _cleanup_free_ char *line = NULL;
        long unsigned ppid;
        const char *p;

        assert(pid >= 0);
        assert(_ppid);

        if (pid == 0 || pid == getpid_cached()) {
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

                        return negative_errno();
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
int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags) {
        _cleanup_free_ char *buffer = NULL;
        siginfo_t status;
        int r, prio;

        assert(pid > 1);

        if (!name) {
                r = get_process_comm(pid, &buffer);
                if (r < 0)
                        log_debug_errno(r, "Failed to acquire process name of " PID_FMT ", ignoring: %m", pid);
                else
                        name = buffer;
        }

        prio = flags & WAIT_LOG_ABNORMAL ? LOG_ERR : LOG_DEBUG;

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return log_full_errno(prio, r, "Failed to wait for %s: %m", strna(name));

        if (status.si_code == CLD_EXITED) {
                if (status.si_status != EXIT_SUCCESS)
                        log_full(flags & WAIT_LOG_NON_ZERO_EXIT_STATUS ? LOG_ERR : LOG_DEBUG,
                                 "%s failed with exit status %i.", strna(name), status.si_status);
                else
                        log_debug("%s succeeded.", name);

                return status.si_status;

        } else if (IN_SET(status.si_code, CLD_KILLED, CLD_DUMPED)) {

                log_full(prio, "%s terminated by signal %s.", strna(name), signal_to_string(status.si_status));
                return -EPROTO;
        }

        log_full(prio, "%s failed due to unknown reason.", strna(name));
        return -EPROTO;
}

/*
 * Return values:
 *
 * < 0 : wait_for_terminate_with_timeout() failed to get the state of the process, the process timed out, the process
 *       was terminated by a signal, or failed for an unknown reason.
 *
 * >=0 : The process terminated normally with no failures.
 *
 * Success is indicated by a return value of zero, a timeout is indicated by ETIMEDOUT, and all other child failure
 * states are indicated by error is indicated by a non-zero value.
 *
 * This call assumes SIGCHLD has been blocked already, in particular before the child to wait for has been forked off
 * to remain entirely race-free.
 */
int wait_for_terminate_with_timeout(pid_t pid, usec_t timeout) {
        sigset_t mask;
        int r;
        usec_t until;

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);

        /* Drop into a sigtimewait-based timeout. Waiting for the
         * pid to exit. */
        until = now(CLOCK_MONOTONIC) + timeout;
        for (;;) {
                usec_t n;
                siginfo_t status = {};
                struct timespec ts;

                n = now(CLOCK_MONOTONIC);
                if (n >= until)
                        break;

                r = sigtimedwait(&mask, NULL, timespec_store(&ts, until - n)) < 0 ? -errno : 0;
                /* Assuming we woke due to the child exiting. */
                if (waitid(P_PID, pid, &status, WEXITED|WNOHANG) == 0) {
                        if (status.si_pid == pid) {
                                /* This is the correct child.*/
                                if (status.si_code == CLD_EXITED)
                                        return (status.si_status == 0) ? 0 : -EPROTO;
                                else
                                        return -EPROTO;
                        }
                }
                /* Not the child, check for errors and proceed appropriately */
                if (r < 0) {
                        switch (r) {
                        case -EAGAIN:
                                /* Timed out, child is likely hung. */
                                return -ETIMEDOUT;
                        case -EINTR:
                                /* Received a different signal and should retry */
                                continue;
                        default:
                                /* Return any unexpected errors */
                                return r;
                        }
                }
        }

        return -EPROTO;
}

void sigkill_wait(pid_t pid) {
        assert(pid > 1);

        if (kill(pid, SIGKILL) >= 0)
                (void) wait_for_terminate(pid, NULL);
}

void sigkill_waitp(pid_t *pid) {
        PROTECT_ERRNO;

        if (!pid)
                return;
        if (*pid <= 1)
                return;

        sigkill_wait(*pid);
}

void sigterm_wait(pid_t pid) {
        assert(pid > 1);

        if (kill_and_sigcont(pid, SIGTERM) >= 0)
                (void) wait_for_terminate(pid, NULL);
}

int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = kill(pid, sig) < 0 ? -errno : 0;

        /* If this worked, also send SIGCONT, unless we already just sent a SIGCONT, or SIGKILL was sent which isn't
         * affected by a process being suspended anyway. */
        if (r >= 0 && !IN_SET(sig, SIGCONT, SIGKILL))
                (void) kill(pid, SIGCONT);

        return r;
}

int getenv_for_pid(pid_t pid, const char *field, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        char *value = NULL;
        const char *path;
        size_t l, sum = 0;
        int r;

        assert(pid >= 0);
        assert(field);
        assert(ret);

        if (pid == 0 || pid == getpid_cached()) {
                const char *e;

                e = getenv(field);
                if (!e) {
                        *ret = NULL;
                        return 0;
                }

                value = strdup(e);
                if (!value)
                        return -ENOMEM;

                *ret = value;
                return 1;
        }

        if (!pid_is_valid(pid))
                return -EINVAL;

        path = procfs_file_alloca(pid, "environ");

        r = fopen_unlocked(path, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        l = strlen(field);
        for (;;) {
                _cleanup_free_ char *line = NULL;

                if (sum > ENVIRONMENT_BLOCK_MAX) /* Give up searching eventually */
                        return -ENOBUFS;

                r = read_nul_string(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)  /* EOF */
                        break;

                sum += r;

                if (strneq(line, field, l) && line[l] == '=') {
                        value = strdup(line + l + 1);
                        if (!value)
                                return -ENOMEM;

                        *ret = value;
                        return 1;
                }
        }

        *ret = NULL;
        return 0;
}

int pid_is_my_child(pid_t pid) {
        pid_t ppid;
        int r;

        if (pid <= 1)
                return false;

        r = get_process_ppid(pid, &ppid);
        if (r < 0)
                return r;

        return ppid == getpid_cached();
}

bool pid_is_unwaited(pid_t pid) {
        /* Checks whether a PID is still valid at all, including a zombie */

        if (pid < 0)
                return false;

        if (pid <= 1) /* If we or PID 1 would be dead and have been waited for, this code would not be running */
                return true;

        if (pid == getpid_cached())
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

        if (pid == getpid_cached())
                return true;

        r = get_process_state(pid);
        if (IN_SET(r, -ESRCH, 'Z'))
                return false;

        return true;
}

int pid_from_same_root_fs(pid_t pid) {
        const char *root;

        if (pid < 0)
                return false;

        if (pid == 0 || pid == getpid_cached())
                return true;

        root = procfs_file_alloca(pid, "root");

        return files_same(root, "/proc/1/root", 0);
}

bool is_main_thread(void) {
        static thread_local int cached = 0;

        if (_unlikely_(cached == 0))
                cached = getpid_cached() == gettid() ? 1 : -1;

        return cached > 0;
}

_noreturn_ void freeze(void) {

        log_close();

        /* Make sure nobody waits for us on a socket anymore */
        (void) close_all_fds(NULL, 0);

        sync();

        /* Let's not freeze right away, but keep reaping zombies. */
        for (;;) {
                int r;
                siginfo_t si = {};

                r = waitid(P_ALL, 0, &si, WEXITED);
                if (r < 0 && errno != EINTR)
                        break;
        }

        /* waitid() failed with an unexpected error, things are really borked. Freeze now! */
        for (;;)
                pause();
}

bool oom_score_adjust_is_valid(int oa) {
        return oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX;
}

unsigned long personality_from_string(const char *p) {
        int architecture;

        if (!p)
                return PERSONALITY_INVALID;

        /* Parse a personality specifier. We use our own identifiers that indicate specific ABIs, rather than just
         * hints regarding the register size, since we want to keep things open for multiple locally supported ABIs for
         * the same register size. */

        architecture = architecture_from_string(p);
        if (architecture < 0)
                return PERSONALITY_INVALID;

        if (architecture == native_architecture())
                return PER_LINUX;
#ifdef SECONDARY_ARCHITECTURE
        if (architecture == SECONDARY_ARCHITECTURE)
                return PER_LINUX32;
#endif

        return PERSONALITY_INVALID;
}

const char* personality_to_string(unsigned long p) {
        int architecture = _ARCHITECTURE_INVALID;

        if (p == PER_LINUX)
                architecture = native_architecture();
#ifdef SECONDARY_ARCHITECTURE
        else if (p == PER_LINUX32)
                architecture = SECONDARY_ARCHITECTURE;
#endif

        if (architecture < 0)
                return NULL;

        return architecture_to_string(architecture);
}

int safe_personality(unsigned long p) {
        int ret;

        /* So here's the deal, personality() is weirdly defined by glibc. In some cases it returns a failure via errno,
         * and in others as negative return value containing an errno-like value. Let's work around this: this is a
         * wrapper that uses errno if it is set, and uses the return value otherwise. And then it sets both errno and
         * the return value indicating the same issue, so that we are definitely on the safe side.
         *
         * See https://github.com/systemd/systemd/issues/6737 */

        errno = 0;
        ret = personality(p);
        if (ret < 0) {
                if (errno != 0)
                        return -errno;

                errno = -ret;
        }

        return ret;
}

int opinionated_personality(unsigned long *ret) {
        int current;

        /* Returns the current personality, or PERSONALITY_INVALID if we can't determine it. This function is a bit
         * opinionated though, and ignores all the finer-grained bits and exotic personalities, only distinguishing the
         * two most relevant personalities: PER_LINUX and PER_LINUX32. */

        current = safe_personality(PERSONALITY_INVALID);
        if (current < 0)
                return current;

        if (((unsigned long) current & 0xffff) == PER_LINUX32)
                *ret = PER_LINUX32;
        else
                *ret = PER_LINUX;

        return 0;
}

void valgrind_summary_hack(void) {
#if HAVE_VALGRIND_VALGRIND_H
        if (getpid_cached() == 1 && RUNNING_ON_VALGRIND) {
                pid_t pid;
                pid = raw_clone(SIGCHLD);
                if (pid < 0)
                        log_emergency_errno(errno, "Failed to fork off valgrind helper: %m");
                else if (pid == 0)
                        exit(EXIT_SUCCESS);
                else {
                        log_info("Spawned valgrind helper as PID "PID_FMT".", pid);
                        (void) wait_for_terminate(pid, NULL);
                }
        }
#endif
}

int pid_compare_func(const pid_t *a, const pid_t *b) {
        /* Suitable for usage in qsort() */
        return CMP(*a, *b);
}

int ioprio_parse_priority(const char *s, int *ret) {
        int i, r;

        assert(s);
        assert(ret);

        r = safe_atoi(s, &i);
        if (r < 0)
                return r;

        if (!ioprio_priority_is_valid(i))
                return -EINVAL;

        *ret = i;
        return 0;
}

/* The cached PID, possible values:
 *
 *     == UNSET [0]  → cache not initialized yet
 *     == BUSY [-1]  → some thread is initializing it at the moment
 *     any other     → the cached PID
 */

#define CACHED_PID_UNSET ((pid_t) 0)
#define CACHED_PID_BUSY ((pid_t) -1)

static pid_t cached_pid = CACHED_PID_UNSET;

void reset_cached_pid(void) {
        /* Invoked in the child after a fork(), i.e. at the first moment the PID changed */
        cached_pid = CACHED_PID_UNSET;
}

/* We use glibc __register_atfork() + __dso_handle directly here, as they are not included in the glibc
 * headers. __register_atfork() is mostly equivalent to pthread_atfork(), but doesn't require us to link against
 * libpthread, as it is part of glibc anyway. */
extern int __register_atfork(void (*prepare) (void), void (*parent) (void), void (*child) (void), void *dso_handle);
extern void* __dso_handle _weak_;

pid_t getpid_cached(void) {
        static bool installed = false;
        pid_t current_value;

        /* getpid_cached() is much like getpid(), but caches the value in local memory, to avoid having to invoke a
         * system call each time. This restores glibc behaviour from before 2.24, when getpid() was unconditionally
         * cached. Starting with 2.24 getpid() started to become prohibitively expensive when used for detecting when
         * objects were used across fork()s. With this caching the old behaviour is somewhat restored.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=1443976
         * https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=c579f48edba88380635ab98cb612030e3ed8691e
         */

        current_value = __sync_val_compare_and_swap(&cached_pid, CACHED_PID_UNSET, CACHED_PID_BUSY);

        switch (current_value) {

        case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
                pid_t new_pid;

                new_pid = raw_getpid();

                if (!installed) {
                        /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
                         * only half-documented (glibc doesn't document it but LSB does — though only superficially)
                         * we'll check for errors only in the most generic fashion possible. */

                        if (__register_atfork(NULL, NULL, reset_cached_pid, __dso_handle) != 0) {
                                /* OOM? Let's try again later */
                                cached_pid = CACHED_PID_UNSET;
                                return new_pid;
                        }

                        installed = true;
                }

                cached_pid = new_pid;
                return new_pid;
        }

        case CACHED_PID_BUSY: /* Somebody else is currently initializing */
                return raw_getpid();

        default: /* Properly initialized */
                return current_value;
        }
}

int must_be_root(void) {

        if (geteuid() == 0)
                return 0;

        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be root.");
}

int safe_fork_full(
                const char *name,
                const int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid) {

        pid_t original_pid, pid;
        sigset_t saved_ss, ss;
        bool block_signals = false;
        int prio, r;

        /* A wrapper around fork(), that does a couple of important initializations in addition to mere forking. Always
         * returns the child's PID in *ret_pid. Returns == 0 in the child, and > 0 in the parent. */

        prio = flags & FORK_LOG ? LOG_ERR : LOG_DEBUG;

        original_pid = getpid_cached();

        if (flags & (FORK_RESET_SIGNALS|FORK_DEATHSIG)) {
                /* We temporarily block all signals, so that the new child has them blocked initially. This way, we can
                 * be sure that SIGTERMs are not lost we might send to the child. */

                assert_se(sigfillset(&ss) >= 0);
                block_signals = true;

        } else if (flags & FORK_WAIT) {
                /* Let's block SIGCHLD at least, so that we can safely watch for the child process */

                assert_se(sigemptyset(&ss) >= 0);
                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                block_signals = true;
        }

        if (block_signals)
                if (sigprocmask(SIG_SETMASK, &ss, &saved_ss) < 0)
                        return log_full_errno(prio, errno, "Failed to set signal mask: %m");

        if (flags & FORK_NEW_MOUNTNS)
                pid = raw_clone(SIGCHLD|CLONE_NEWNS);
        else
                pid = fork();
        if (pid < 0) {
                r = -errno;

                if (block_signals) /* undo what we did above */
                        (void) sigprocmask(SIG_SETMASK, &saved_ss, NULL);

                return log_full_errno(prio, r, "Failed to fork: %m");
        }
        if (pid > 0) {
                /* We are in the parent process */

                log_debug("Successfully forked off '%s' as PID " PID_FMT ".", strna(name), pid);

                if (flags & FORK_WAIT) {
                        r = wait_for_terminate_and_check(name, pid, (flags & FORK_LOG ? WAIT_LOG : 0));
                        if (r < 0)
                                return r;
                        if (r != EXIT_SUCCESS) /* exit status > 0 should be treated as failure, too */
                                return -EPROTO;
                }

                if (block_signals) /* undo what we did above */
                        (void) sigprocmask(SIG_SETMASK, &saved_ss, NULL);

                if (ret_pid)
                        *ret_pid = pid;

                return 1;
        }

        /* We are in the child process */

        if (flags & FORK_REOPEN_LOG) {
                /* Close the logs if requested, before we log anything. And make sure we reopen it if needed. */
                log_close();
                log_set_open_when_needed(true);
        }

        if (name) {
                r = rename_process(name);
                if (r < 0)
                        log_full_errno(flags & FORK_LOG ? LOG_WARNING : LOG_DEBUG,
                                       r, "Failed to rename process, ignoring: %m");
        }

        if (flags & FORK_DEATHSIG)
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
                        log_full_errno(prio, errno, "Failed to set death signal: %m");
                        _exit(EXIT_FAILURE);
                }

        if (flags & FORK_RESET_SIGNALS) {
                r = reset_all_signal_handlers();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to reset signal handlers: %m");
                        _exit(EXIT_FAILURE);
                }

                /* This implicitly undoes the signal mask stuff we did before the fork()ing above */
                r = reset_signal_mask();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to reset signal mask: %m");
                        _exit(EXIT_FAILURE);
                }
        } else if (block_signals) { /* undo what we did above */
                if (sigprocmask(SIG_SETMASK, &saved_ss, NULL) < 0) {
                        log_full_errno(prio, errno, "Failed to restore signal mask: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_DEATHSIG) {
                pid_t ppid;
                /* Let's see if the parent PID is still the one we started from? If not, then the parent
                 * already died by the time we set PR_SET_PDEATHSIG, hence let's emulate the effect */

                ppid = getppid();
                if (ppid == 0)
                        /* Parent is in a differn't PID namespace. */;
                else if (ppid != original_pid) {
                        log_debug("Parent died early, raising SIGTERM.");
                        (void) raise(SIGTERM);
                        _exit(EXIT_FAILURE);
                }
        }

        if (FLAGS_SET(flags, FORK_NEW_MOUNTNS | FORK_MOUNTNS_SLAVE)) {

                /* Optionally, make sure we never propagate mounts to the host. */

                if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
                        log_full_errno(prio, errno, "Failed to remount root directory as MS_SLAVE: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_CLOSE_ALL_FDS) {
                /* Close the logs here in case it got reopened above, as close_all_fds() would close them for us */
                log_close();

                r = close_all_fds(except_fds, n_except_fds);
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to close all file descriptors: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        /* When we were asked to reopen the logs, do so again now */
        if (flags & FORK_REOPEN_LOG) {
                log_open();
                log_set_open_when_needed(false);
        }

        if (flags & FORK_NULL_STDIO) {
                r = make_null_stdio();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to connect stdin/stdout to /dev/null: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_RLIMIT_NOFILE_SAFE) {
                r = rlimit_nofile_safe();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to lower RLIMIT_NOFILE's soft limit to 1K: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (ret_pid)
                *ret_pid = getpid_cached();

        return 0;
}

int namespace_fork(
                const char *outer_name,
                const char *inner_name,
                const int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                int pidns_fd,
                int mntns_fd,
                int netns_fd,
                int userns_fd,
                int root_fd,
                pid_t *ret_pid) {

        int r;

        /* This is much like safe_fork(), but forks twice, and joins the specified namespaces in the middle
         * process. This ensures that we are fully a member of the destination namespace, with pidns an all, so that
         * /proc/self/fd works correctly. */

        r = safe_fork_full(outer_name, except_fds, n_except_fds, (flags|FORK_DEATHSIG) & ~(FORK_REOPEN_LOG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE), ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                pid_t pid;

                /* Child */

                r = namespace_enter(pidns_fd, mntns_fd, netns_fd, userns_fd, root_fd);
                if (r < 0) {
                        log_full_errno(FLAGS_SET(flags, FORK_LOG) ? LOG_ERR : LOG_DEBUG, r, "Failed to join namespace: %m");
                        _exit(EXIT_FAILURE);
                }

                /* We mask a few flags here that either make no sense for the grandchild, or that we don't have to do again */
                r = safe_fork_full(inner_name, except_fds, n_except_fds, flags & ~(FORK_WAIT|FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_NULL_STDIO), &pid);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                if (r == 0) {
                        /* Child */
                        if (ret_pid)
                                *ret_pid = pid;
                        return 0;
                }

                r = wait_for_terminate_and_check(inner_name, pid, FLAGS_SET(flags, FORK_LOG) ? WAIT_LOG : 0);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(r);
        }

        return 1;
}

int fork_agent(const char *name, const int except[], size_t n_except, pid_t *ret_pid, const char *path, ...) {
        bool stdout_is_tty, stderr_is_tty;
        size_t n, i;
        va_list ap;
        char **l;
        int r;

        assert(path);

        /* Spawns a temporary TTY agent, making sure it goes away when we go away */

        r = safe_fork_full(name, except, n_except, FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS, ret_pid);
        if (r < 0)
                return r;
        if (r > 0)
                return 0;

        /* In the child: */

        stdout_is_tty = isatty(STDOUT_FILENO);
        stderr_is_tty = isatty(STDERR_FILENO);

        if (!stdout_is_tty || !stderr_is_tty) {
                int fd;

                /* Detach from stdout/stderr. and reopen
                 * /dev/tty for them. This is important to
                 * ensure that when systemctl is started via
                 * popen() or a similar call that expects to
                 * read EOF we actually do generate EOF and
                 * not delay this indefinitely by because we
                 * keep an unused copy of stdin around. */
                fd = open("/dev/tty", O_WRONLY);
                if (fd < 0) {
                        log_error_errno(errno, "Failed to open /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stdout_is_tty && dup2(fd, STDOUT_FILENO) < 0) {
                        log_error_errno(errno, "Failed to dup2 /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stderr_is_tty && dup2(fd, STDERR_FILENO) < 0) {
                        log_error_errno(errno, "Failed to dup2 /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                safe_close_above_stdio(fd);
        }

        (void) rlimit_nofile_safe();

        /* Count arguments */
        va_start(ap, path);
        for (n = 0; va_arg(ap, char*); n++)
                ;
        va_end(ap);

        /* Allocate strv */
        l = newa(char*, n + 1);

        /* Fill in arguments */
        va_start(ap, path);
        for (i = 0; i <= n; i++)
                l[i] = va_arg(ap, char*);
        va_end(ap);

        execv(path, l);
        _exit(EXIT_FAILURE);
}

int set_oom_score_adjust(int value) {
        char t[DECIMAL_STR_MAX(int)];

        sprintf(t, "%i", value);

        return write_string_file("/proc/self/oom_score_adj", t,
                                 WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_DISABLE_BUFFER);
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ioprio_class, int, IOPRIO_N_CLASSES);

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
        [SCHED_RR] = "rr",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(sched_policy, int, INT_MAX);
