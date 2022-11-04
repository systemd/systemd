/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/oom.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_sched.h"
#include "missing_syscall.h"
#include "namespace-util.h"
#include "path-util.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "stdio-util.h"
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
        _cleanup_free_ char *line = NULL;
        const char *p;
        char state;
        int r;

        assert(pid >= 0);

        /* Shortcut: if we are enquired about our own state, we are obviously running */
        if (pid == 0 || pid == getpid_cached())
                return (unsigned char) 'R';

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
        int r;

        assert(ret);
        assert(pid >= 0);

        if (pid == 0 || pid == getpid_cached()) {
                comm = new0(char, TASK_COMM_LEN + 1); /* Must fit in 16 byte according to prctl(2) */
                if (!comm)
                        return -ENOMEM;

                if (prctl(PR_GET_NAME, comm) < 0)
                        return -errno;
        } else {
                const char *p;

                p = procfs_file_alloca(pid, "comm");

                /* Note that process names of kernel threads can be much longer than TASK_COMM_LEN */
                r = read_one_line_file(p, &comm);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;
        }

        escaped = new(char, COMM_MAX_LEN);
        if (!escaped)
                return -ENOMEM;

        /* Escape unprintable characters, just in case, but don't grow the string beyond the underlying size */
        cellescape(escaped, COMM_MAX_LEN, comm);

        *ret = TAKE_PTR(escaped);
        return 0;
}

static int get_process_cmdline_nulstr(
                pid_t pid,
                size_t max_size,
                ProcessCmdlineFlags flags,
                char **ret,
                size_t *ret_size) {

        const char *p;
        char *t;
        size_t k;
        int r;

        /* Retrieves a process' command line as a "sized nulstr", i.e. possibly without the last NUL, but
         * with a specified size.
         *
         * If PROCESS_CMDLINE_COMM_FALLBACK is specified in flags and the process has no command line set
         * (the case for kernel threads), or has a command line that resolves to the empty string, will
         * return the "comm" name of the process instead. This will use at most _SC_ARG_MAX bytes of input
         * data.
         *
         * Returns an error, 0 if output was read but is truncated, 1 otherwise.
         */

        p = procfs_file_alloca(pid, "cmdline");
        r = read_virtual_file(p, max_size, &t, &k); /* Let's assume that each input byte results in >= 1
                                                     * columns of output. We ignore zero-width codepoints. */
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        if (k == 0) {
                t = mfree(t);

                if (!(flags & PROCESS_CMDLINE_COMM_FALLBACK))
                        return -ENOENT;

                /* Kernel threads have no argv[] */
                _cleanup_free_ char *comm = NULL;

                r = get_process_comm(pid, &comm);
                if (r < 0)
                        return r;

                t = strjoin("[", comm, "]");
                if (!t)
                        return -ENOMEM;

                k = strlen(t);
                r = k <= max_size;
                if (r == 0) /* truncation */
                        t[max_size] = '\0';
        }

        *ret = t;
        *ret_size = k;
        return r;
}

int get_process_cmdline(pid_t pid, size_t max_columns, ProcessCmdlineFlags flags, char **ret) {
        _cleanup_free_ char *t = NULL;
        size_t k;
        char *ans;

        assert(pid >= 0);
        assert(ret);

        /* Retrieve and format a commandline. See above for discussion of retrieval options.
         *
         * There are two main formatting modes:
         *
         * - when PROCESS_CMDLINE_QUOTE is specified, output is quoted in C/Python style. If no shell special
         *   characters are present, this output can be copy-pasted into the terminal to execute. UTF-8
         *   output is assumed.
         *
         * - otherwise, a compact non-roundtrippable form is returned. Non-UTF8 bytes are replaced by �. The
         *   returned string is of the specified console width at most, abbreviated with an ellipsis.
         *
         * Returns -ESRCH if the process doesn't exist, and -ENOENT if the process has no command line (and
         * PROCESS_CMDLINE_COMM_FALLBACK is not specified). Returns 0 and sets *line otherwise. */

        int full = get_process_cmdline_nulstr(pid, max_columns, flags, &t, &k);
        if (full < 0)
                return full;

        if (flags & (PROCESS_CMDLINE_QUOTE | PROCESS_CMDLINE_QUOTE_POSIX)) {
                ShellEscapeFlags shflags = SHELL_ESCAPE_EMPTY |
                        FLAGS_SET(flags, PROCESS_CMDLINE_QUOTE_POSIX) * SHELL_ESCAPE_POSIX;

                assert(!(flags & PROCESS_CMDLINE_USE_LOCALE));

                _cleanup_strv_free_ char **args = NULL;

                args = strv_parse_nulstr(t, k);
                if (!args)
                        return -ENOMEM;

                /* Drop trailing empty strings. See issue #21186. */
                STRV_FOREACH_BACKWARDS(p, args) {
                        if (!isempty(*p))
                                break;

                        *p = mfree(*p);
                }

                ans = quote_command_line(args, shflags);
                if (!ans)
                        return -ENOMEM;
        } else {
                /* Arguments are separated by NULs. Let's replace those with spaces. */
                for (size_t i = 0; i < k - 1; i++)
                        if (t[i] == '\0')
                                t[i] = ' ';

                delete_trailing_chars(t, WHITESPACE);

                bool eight_bit = (flags & PROCESS_CMDLINE_USE_LOCALE) && !is_locale_utf8();

                ans = escape_non_printable_full(t, max_columns,
                                                eight_bit * XESCAPE_8_BIT | !full * XESCAPE_FORCE_ELLIPSIS);
                if (!ans)
                        return -ENOMEM;

                ans = str_realloc(ans);
        }

        *ret = ans;
        return 0;
}

static int update_argv(const char name[], size_t l) {
        static int can_do = -1;

        if (can_do == 0)
                return 0;
        can_do = false; /* We'll set it to true only if the whole process works */

        /* Let's not bother with this if we don't have euid == 0. Strictly speaking we should check for the
         * CAP_SYS_RESOURCE capability which is independent of the euid. In our own code the capability generally is
         * present only for euid == 0, hence let's use this as quick bypass check, to avoid calling mmap() if
         * PR_SET_MM_ARG_{START,END} fails with EPERM later on anyway. After all geteuid() is dead cheap to call, but
         * mmap() is not. */
        if (geteuid() != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Skipping PR_SET_MM, as we don't have privileges.");

        static size_t mm_size = 0;
        static char *mm = NULL;
        int r;

        if (mm_size < l+1) {
                size_t nn_size;
                char *nn;

                nn_size = PAGE_ALIGN(l+1);
                nn = mmap(NULL, nn_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (nn == MAP_FAILED)
                        return log_debug_errno(errno, "mmap() failed: %m");

                strncpy(nn, name, nn_size);

                /* Now, let's tell the kernel about this new memory */
                if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0) {
                        if (ERRNO_IS_PRIVILEGE(errno))
                                return log_debug_errno(errno, "PR_SET_MM_ARG_START failed: %m");

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
                                r = log_debug_errno(errno, "PR_SET_MM_ARG_END hack failed, proceeding without: %m");
                                (void) munmap(nn, nn_size);
                                return r;
                        }

                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0)
                                return log_debug_errno(errno, "PR_SET_MM_ARG_START still failed, proceeding without: %m");
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

        can_do = true;
        return 0;
}

int rename_process(const char name[]) {
        bool truncated = false;

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

        size_t l = strlen(name);

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
        (void) update_argv(name, l);

        /* Fourth step: in all cases we'll also update the original argv[], so that our own code gets it right too if
         * it still looks here */
        if (saved_argc > 0) {
                if (saved_argv[0]) {
                        size_t k;

                        k = strlen(saved_argv[0]);
                        strncpy(saved_argv[0], name, k);
                        if (l > k)
                                truncated = true;
                }

                for (int i = 1; i < saved_argc; i++) {
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

int get_process_capeff(pid_t pid, char **ret) {
        const char *p;
        int r;

        assert(pid >= 0);
        assert(ret);

        p = procfs_file_alloca(pid, "status");

        r = get_proc_field(p, "CapEff", WHITESPACE, ret);
        if (r == -ENOENT)
                return -ESRCH;

        return r;
}

static int get_process_link_contents(pid_t pid, const char *proc_file, char **ret) {
        const char *p;
        int r;

        assert(proc_file);

        p = procfs_file_alloca(pid, proc_file);

        r = readlink_malloc(p, ret);
        return r == -ENOENT ? -ESRCH : r;
}

int get_process_exe(pid_t pid, char **ret) {
        char *d;
        int r;

        assert(pid >= 0);

        r = get_process_link_contents(pid, "exe", ret);
        if (r < 0)
                return r;

        if (ret) {
                d = endswith(*ret, " (deleted)");
                if (d)
                        *d = '\0';
        }

        return 0;
}

static int get_process_id(pid_t pid, const char *field, uid_t *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r;

        assert(field);
        assert(ret);

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

                        return parse_uid(l, ret);
                }
        }

        return -EIO;
}

int get_process_uid(pid_t pid, uid_t *ret) {

        if (pid == 0 || pid == getpid_cached()) {
                *ret = getuid();
                return 0;
        }

        return get_process_id(pid, "Uid:", ret);
}

int get_process_gid(pid_t pid, gid_t *ret) {

        if (pid == 0 || pid == getpid_cached()) {
                *ret = getgid();
                return 0;
        }

        assert_cc(sizeof(uid_t) == sizeof(gid_t));
        return get_process_id(pid, "Gid:", ret);
}

int get_process_cwd(pid_t pid, char **ret) {
        assert(pid >= 0);

        if (pid == 0 || pid == getpid_cached())
                return safe_getcwd(ret);

        return get_process_link_contents(pid, "cwd", ret);
}

int get_process_root(pid_t pid, char **ret) {
        assert(pid >= 0);
        return get_process_link_contents(pid, "root", ret);
}

#define ENVIRONMENT_BLOCK_MAX (5U*1024U*1024U)

int get_process_environ(pid_t pid, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *outcome = NULL;
        size_t sz = 0;
        const char *p;
        int r;

        assert(pid >= 0);
        assert(ret);

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

                if (!GREEDY_REALLOC(outcome, sz + 5))
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
        *ret = TAKE_PTR(outcome);

        return 0;
}

int get_process_ppid(pid_t pid, pid_t *ret) {
        _cleanup_free_ char *line = NULL;
        unsigned long ppid;
        const char *p;
        int r;

        assert(pid >= 0);

        if (pid == 0 || pid == getpid_cached()) {
                if (ret)
                        *ret = getppid();
                return 0;
        }

        if (pid == 1) /* PID 1 has no parent, shortcut this case */
                return -EADDRNOTAVAIL;

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        /* Let's skip the pid and comm fields. The latter is enclosed in () but does not escape any () in its
         * value, so let's skip over it manually */

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%lu ", /* ppid */
                   &ppid) != 1)
                return -EIO;

        /* If ppid is zero the process has no parent. Which might be the case for PID 1 but also for
         * processes originating in other namespaces that are inserted into a pidns. Return a recognizable
         * error in this case. */
        if (ppid == 0)
                return -EADDRNOTAVAIL;

        if ((pid_t) ppid < 0 || (unsigned long) (pid_t) ppid != ppid)
                return -ERANGE;

        if (ret)
                *ret = (pid_t) ppid;

        return 0;
}

int get_process_umask(pid_t pid, mode_t *ret) {
        _cleanup_free_ char *m = NULL;
        const char *p;
        int r;

        assert(pid >= 0);
        assert(ret);

        p = procfs_file_alloca(pid, "status");

        r = get_proc_field(p, "Umask", WHITESPACE, &m);
        if (r == -ENOENT)
                return -ESRCH;

        return parse_mode(m, ret);
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
        until = usec_add(now(CLOCK_MONOTONIC), timeout);
        for (;;) {
                usec_t n;
                siginfo_t status = {};

                n = now(CLOCK_MONOTONIC);
                if (n >= until)
                        break;

                r = RET_NERRNO(sigtimedwait(&mask, NULL, TIMESPEC_STORE(until - n)));
                /* Assuming we woke due to the child exiting. */
                if (waitid(P_PID, pid, &status, WEXITED|WNOHANG) == 0) {
                        if (status.si_pid == pid) {
                                /* This is the correct child. */
                                if (status.si_code == CLD_EXITED)
                                        return status.si_status == 0 ? 0 : -EPROTO;
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

        (void) kill(pid, SIGKILL);
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

        (void) kill_and_sigcont(pid, SIGTERM);
        (void) wait_for_terminate(pid, NULL);
}

int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = RET_NERRNO(kill(pid, sig));

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

bool oom_score_adjust_is_valid(int oa) {
        return oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX;
}

unsigned long personality_from_string(const char *p) {
        Architecture architecture;

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
#ifdef ARCHITECTURE_SECONDARY
        if (architecture == ARCHITECTURE_SECONDARY)
                return PER_LINUX32;
#endif

        return PERSONALITY_INVALID;
}

const char* personality_to_string(unsigned long p) {
        Architecture architecture = _ARCHITECTURE_INVALID;

        if (p == PER_LINUX)
                architecture = native_architecture();
#ifdef ARCHITECTURE_SECONDARY
        else if (p == PER_LINUX32)
                architecture = ARCHITECTURE_SECONDARY;
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

pid_t getpid_cached(void) {
        static bool installed = false;
        pid_t current_value = CACHED_PID_UNSET;

        /* getpid_cached() is much like getpid(), but caches the value in local memory, to avoid having to invoke a
         * system call each time. This restores glibc behaviour from before 2.24, when getpid() was unconditionally
         * cached. Starting with 2.24 getpid() started to become prohibitively expensive when used for detecting when
         * objects were used across fork()s. With this caching the old behaviour is somewhat restored.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=1443976
         * https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=c579f48edba88380635ab98cb612030e3ed8691e
         */

        __atomic_compare_exchange_n(
                        &cached_pid,
                        &current_value,
                        CACHED_PID_BUSY,
                        false,
                        __ATOMIC_SEQ_CST,
                        __ATOMIC_SEQ_CST);

        switch (current_value) {

        case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
                pid_t new_pid;

                new_pid = raw_getpid();

                if (!installed) {
                        /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
                         * only half-documented (glibc doesn't document it but LSB does — though only superficially)
                         * we'll check for errors only in the most generic fashion possible. */

                        if (pthread_atfork(NULL, NULL, reset_cached_pid) != 0) {
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

static void restore_sigsetp(sigset_t **ssp) {
        if (*ssp)
                (void) sigprocmask(SIG_SETMASK, *ssp, NULL);
}

int safe_fork_full(
                const char *name,
                const int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid) {

        pid_t original_pid, pid;
        sigset_t saved_ss, ss;
        _unused_ _cleanup_(restore_sigsetp) sigset_t *saved_ssp = NULL;
        bool block_signals = false, block_all = false;
        int prio, r;

        /* A wrapper around fork(), that does a couple of important initializations in addition to mere forking. Always
         * returns the child's PID in *ret_pid. Returns == 0 in the child, and > 0 in the parent. */

        prio = flags & FORK_LOG ? LOG_ERR : LOG_DEBUG;

        original_pid = getpid_cached();

        if (flags & FORK_FLUSH_STDIO) {
                fflush(stdout);
                fflush(stderr); /* This one shouldn't be necessary, stderr should be unbuffered anyway, but let's better be safe than sorry */
        }

        if (flags & (FORK_RESET_SIGNALS|FORK_DEATHSIG)) {
                /* We temporarily block all signals, so that the new child has them blocked initially. This way, we can
                 * be sure that SIGTERMs are not lost we might send to the child. */

                assert_se(sigfillset(&ss) >= 0);
                block_signals = block_all = true;

        } else if (flags & FORK_WAIT) {
                /* Let's block SIGCHLD at least, so that we can safely watch for the child process */

                assert_se(sigemptyset(&ss) >= 0);
                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                block_signals = true;
        }

        if (block_signals) {
                if (sigprocmask(SIG_SETMASK, &ss, &saved_ss) < 0)
                        return log_full_errno(prio, errno, "Failed to set signal mask: %m");
                saved_ssp = &saved_ss;
        }

        if ((flags & (FORK_NEW_MOUNTNS|FORK_NEW_USERNS)) != 0)
                pid = raw_clone(SIGCHLD|
                                (FLAGS_SET(flags, FORK_NEW_MOUNTNS) ? CLONE_NEWNS : 0) |
                                (FLAGS_SET(flags, FORK_NEW_USERNS) ? CLONE_NEWUSER : 0));
        else
                pid = fork();
        if (pid < 0)
                return log_full_errno(prio, errno, "Failed to fork: %m");
        if (pid > 0) {
                /* We are in the parent process */

                log_debug("Successfully forked off '%s' as PID " PID_FMT ".", strna(name), pid);

                if (flags & FORK_WAIT) {
                        if (block_all) {
                                /* undo everything except SIGCHLD */
                                ss = saved_ss;
                                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                                (void) sigprocmask(SIG_SETMASK, &ss, NULL);
                        }

                        r = wait_for_terminate_and_check(name, pid, (flags & FORK_LOG ? WAIT_LOG : 0));
                        if (r < 0)
                                return r;
                        if (r != EXIT_SUCCESS) /* exit status > 0 should be treated as failure, too */
                                return -EPROTO;
                }

                if (ret_pid)
                        *ret_pid = pid;

                return 1;
        }

        /* We are in the child process */

        /* Restore signal mask manually */
        saved_ssp = NULL;

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

        if (flags & (FORK_DEATHSIG|FORK_DEATHSIG_SIGINT))
                if (prctl(PR_SET_PDEATHSIG, (flags & FORK_DEATHSIG_SIGINT) ? SIGINT : SIGTERM) < 0) {
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
                        /* Parent is in a different PID namespace. */;
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

        if (flags & FORK_CLOEXEC_OFF) {
                r = fd_cloexec_many(except_fds, n_except_fds, false);
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to turn off O_CLOEXEC on file descriptors: %m");
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

        } else if (flags & FORK_STDOUT_TO_STDERR) {
                if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
                        log_full_errno(prio, errno, "Failed to connect stdout to stderr: %m");
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

int set_oom_score_adjust(int value) {
        char t[DECIMAL_STR_MAX(int)];

        xsprintf(t, "%i", value);

        return write_string_file("/proc/self/oom_score_adj", t,
                                 WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_DISABLE_BUFFER);
}

int get_oom_score_adjust(int *ret) {
        _cleanup_free_ char *t = NULL;
        int r, a;

        r = read_virtual_file("/proc/self/oom_score_adj", SIZE_MAX, &t, NULL);
        if (r < 0)
                return r;

        delete_trailing_chars(t, WHITESPACE);

        assert_se(safe_atoi(t, &a) >= 0);
        assert_se(oom_score_adjust_is_valid(a));

        if (ret)
                *ret = a;
        return 0;
}

int pidfd_get_pid(int fd, pid_t *ret) {
        char path[STRLEN("/proc/self/fdinfo/") + DECIMAL_STR_MAX(int)];
        _cleanup_free_ char *fdinfo = NULL;
        char *p;
        int r;

        if (fd < 0)
                return -EBADF;

        xsprintf(path, "/proc/self/fdinfo/%i", fd);

        r = read_full_virtual_file(path, &fdinfo, NULL);
        if (r == -ENOENT) /* if fdinfo doesn't exist we assume the process does not exist */
                return -ESRCH;
        if (r < 0)
                return r;

        p = startswith(fdinfo, "Pid:");
        if (!p) {
                p = strstr(fdinfo, "\nPid:");
                if (!p)
                        return -ENOTTY; /* not a pidfd? */

                p += 5;
        }

        p += strspn(p, WHITESPACE);
        p[strcspn(p, WHITESPACE)] = 0;

        return parse_pid(p, ret);
}

static int rlimit_to_nice(rlim_t limit) {
        if (limit <= 1)
                return PRIO_MAX-1; /* i.e. 19 */

        if (limit >= -PRIO_MIN + PRIO_MAX)
                return PRIO_MIN; /* i.e. -20 */

        return PRIO_MAX - (int) limit;
}

int setpriority_closest(int priority) {
        int current, limit, saved_errno;
        struct rlimit highest;

        /* Try to set requested nice level */
        if (setpriority(PRIO_PROCESS, 0, priority) >= 0)
                return 1;

        /* Permission failed */
        saved_errno = -errno;
        if (!ERRNO_IS_PRIVILEGE(saved_errno))
                return saved_errno;

        errno = 0;
        current = getpriority(PRIO_PROCESS, 0);
        if (errno != 0)
                return -errno;

        if (priority == current)
                return 1;

       /* Hmm, we'd expect that raising the nice level from our status quo would always work. If it doesn't,
        * then the whole setpriority() system call is blocked to us, hence let's propagate the error
        * right-away */
        if (priority > current)
                return saved_errno;

        if (getrlimit(RLIMIT_NICE, &highest) < 0)
                return -errno;

        limit = rlimit_to_nice(highest.rlim_cur);

        /* We are already less nice than limit allows us */
        if (current < limit) {
                log_debug("Cannot raise nice level, permissions and the resource limit do not allow it.");
                return 0;
        }

        /* Push to the allowed limit */
        if (setpriority(PRIO_PROCESS, 0, limit) < 0)
                return -errno;

        log_debug("Cannot set requested nice level (%i), used next best (%i).", priority, limit);
        return 0;
}

bool invoked_as(char *argv[], const char *token) {
        if (!argv || isempty(argv[0]))
                return false;

        if (isempty(token))
                return false;

        return strstr(last_path_component(argv[0]), token);
}

bool invoked_by_systemd(void) {
        int r;

        /* If the process is directly executed by PID1 (e.g. ExecStart= or generator), systemd-importd,
         * or systemd-homed, then $SYSTEMD_EXEC_PID= is set, and read the command line. */
        const char *e = getenv("SYSTEMD_EXEC_PID");
        if (!e)
                return false;

        if (streq(e, "*"))
                /* For testing. */
                return true;

        pid_t p;
        r = parse_pid(e, &p);
        if (r < 0) {
                /* We know that systemd sets the variable correctly. Something else must have set it. */
                log_debug_errno(r, "Failed to parse \"SYSTEMD_EXEC_PID=%s\", ignoring: %m", e);
                return false;
        }

        return getpid_cached() == p;
}

_noreturn_ void freeze(void) {
        log_close();

        /* Make sure nobody waits for us (i.e. on one of our sockets) anymore. Note that we use
         * close_all_fds_without_malloc() instead of plain close_all_fds() here, since we want this function
         * to be compatible with being called from signal handlers. */
        (void) close_all_fds_without_malloc(NULL, 0);

        /* Let's not freeze right away, but keep reaping zombies. */
        for (;;) {
                siginfo_t si = {};

                if (waitid(P_ALL, 0, &si, WEXITED) < 0 && errno != EINTR)
                        break;
        }

        /* waitid() failed with an unexpected error, things are really borked. Freeze now! */
        for (;;)
                pause();
}

bool argv_looks_like_help(int argc, char **argv) {
        char **l;

        /* Scans the command line for indications the user asks for help. This is supposed to be called by
         * tools that do not implement getopt() style command line parsing because they are not primarily
         * user-facing. Detects four ways of asking for help:
         *
         * 1. Passing zero arguments
         * 2. Passing "help" as first argument
         * 3. Passing --help as any argument
         * 4. Passing -h as any argument
         */

        if (argc <= 1)
                return true;

        if (streq_ptr(argv[1], "help"))
                return true;

        l = strv_skip(argv, 1);

        return strv_contains(l, "--help") ||
                strv_contains(l, "-h");
}

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
