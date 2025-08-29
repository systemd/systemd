/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/oom.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <syslog.h>
#include <threads.h>
#include <unistd.h>
#if HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif

#include "sd-messages.h"

#include "alloc-util.h"
#include "architecture.h"
#include "argv-util.h"
#include "cgroup-util.h"
#include "dirent-util.h"
#include "env-file.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "locale-util.h"
#include "log.h"
#include "memory-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"

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

int pid_get_comm(pid_t pid, char **ret) {
        _cleanup_free_ char *escaped = NULL, *comm = NULL;
        int r;

        assert(pid >= 0);
        assert(ret);

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

int pidref_get_comm(const PidRef *pid, char **ret) {
        _cleanup_free_ char *comm = NULL;
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        r = pid_get_comm(pid->pid, &comm);
        if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(comm);
        return 0;
}

static int pid_get_cmdline_nulstr(
                pid_t pid,
                size_t max_size,
                ProcessCmdlineFlags flags,
                char **ret,
                size_t *ret_size) {

        _cleanup_free_ char *t = NULL;
        const char *p;
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
                if (!(flags & PROCESS_CMDLINE_COMM_FALLBACK))
                        return -ENOENT;

                /* Kernel threads have no argv[] */
                _cleanup_free_ char *comm = NULL;

                r = pid_get_comm(pid, &comm);
                if (r < 0)
                        return r;

                free(t);
                t = strjoin("[", comm, "]");
                if (!t)
                        return -ENOMEM;

                k = strlen(t);
                r = k <= max_size;
                if (r == 0) /* truncation */
                        t[max_size] = '\0';
        }

        if (ret)
                *ret = TAKE_PTR(t);
        if (ret_size)
                *ret_size = k;

        return r;
}

int pid_get_cmdline(pid_t pid, size_t max_columns, ProcessCmdlineFlags flags, char **ret) {
        _cleanup_free_ char *t = NULL;
        size_t k;
        char *ans;

        assert(pid >= 0);
        assert(ret);

        /* Retrieve and format a command line. See above for discussion of retrieval options.
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

        int full = pid_get_cmdline_nulstr(pid, max_columns, flags, &t, &k);
        if (full < 0)
                return full;

        if (flags & (PROCESS_CMDLINE_QUOTE | PROCESS_CMDLINE_QUOTE_POSIX)) {
                ShellEscapeFlags shflags = SHELL_ESCAPE_EMPTY |
                        FLAGS_SET(flags, PROCESS_CMDLINE_QUOTE_POSIX) * SHELL_ESCAPE_POSIX;

                assert(!(flags & PROCESS_CMDLINE_USE_LOCALE));

                _cleanup_strv_free_ char **args = NULL;

                /* Drop trailing NULs, otherwise strv_parse_nulstr() adds additional empty strings at the end.
                 * See also issue #21186. */
                args = strv_parse_nulstr_full(t, k, /* drop_trailing_nuls = */ true);
                if (!args)
                        return -ENOMEM;

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

int pidref_get_cmdline(const PidRef *pid, size_t max_columns, ProcessCmdlineFlags flags, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        r = pid_get_cmdline(pid->pid, max_columns, flags, &s);
        if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(s);
        return 0;
}

int pid_get_cmdline_strv(pid_t pid, ProcessCmdlineFlags flags, char ***ret) {
        _cleanup_free_ char *t = NULL;
        char **args;
        size_t k;
        int r;

        assert(pid >= 0);
        assert((flags & ~PROCESS_CMDLINE_COMM_FALLBACK) == 0);
        assert(ret);

        r = pid_get_cmdline_nulstr(pid, SIZE_MAX, flags, &t, &k);
        if (r < 0)
                return r;

        args = strv_parse_nulstr_full(t, k, /* drop_trailing_nuls = */ true);
        if (!args)
                return -ENOMEM;

        *ret = args;
        return 0;
}

int pidref_get_cmdline_strv(const PidRef *pid, ProcessCmdlineFlags flags, char ***ret) {
        _cleanup_strv_free_ char **args = NULL;
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        r = pid_get_cmdline_strv(pid->pid, flags, &args);
        if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(args);

        return 0;
}

int container_get_leader(const char *machine, pid_t *pid) {
        _cleanup_free_ char *s = NULL, *class = NULL;
        const char *p;
        pid_t leader;
        int r;

        assert(machine);
        assert(pid);

        if (streq(machine, ".host")) {
                *pid = 1;
                return 0;
        }

        if (!hostname_is_valid(machine, 0))
                return -EINVAL;

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(NULL, p,
                           "LEADER", &s,
                           "CLASS", &class);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -EIO;

        if (!streq_ptr(class, "container"))
                return -EIO;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EIO;

        *pid = leader;
        return 0;
}

int pid_is_kernel_thread(pid_t pid) {
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

int pidref_is_kernel_thread(const PidRef *pid) {
        int result, r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        result = pid_is_kernel_thread(pid->pid);
        if (result < 0)
                return result;

        r = pidref_verify(pid); /* Verify that the PID wasn't reused since */
        if (r < 0)
                return r;

        return result;
}

static int get_process_link_contents(pid_t pid, const char *proc_file, char **ret) {
        const char *p;
        int r;

        assert(proc_file);

        p = procfs_file_alloca(pid, proc_file);

        r = readlink_malloc(p, ret);
        return (r == -ENOENT && proc_mounted() > 0) ? -ESRCH : r;
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

int pid_get_uid(pid_t pid, uid_t *ret) {
        int r;

        assert(pid >= 0);
        assert(ret);

        if (pid == 0 || pid == getpid_cached()) {
                *ret = getuid();
                return 0;
        }

        _cleanup_free_ char *v = NULL;
        r = procfs_file_get_field(pid, "status", "Uid", &v);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        return parse_uid(v, ret);
}

int pidref_get_uid(const PidRef *pid, uid_t *ret) {
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        if (pid->fd >= 0) {
                r = pidfd_get_uid(pid->fd, ret);
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return r;
        }

        uid_t uid;
        r = pid_get_uid(pid->pid, &uid);
        if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (ret)
                *ret = uid;
        return 0;
}

int get_process_gid(pid_t pid, gid_t *ret) {
        int r;

        assert(pid >= 0);
        assert(ret);

        if (pid == 0 || pid == getpid_cached()) {
                *ret = getgid();
                return 0;
        }

        _cleanup_free_ char *v = NULL;
        r = procfs_file_get_field(pid, "status", "Gid", &v);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        return parse_gid(v, ret);
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

int pid_get_ppid(pid_t pid, pid_t *ret) {
        _cleanup_free_ char *line = NULL;
        unsigned long ppid;
        const char *p;
        int r;

        assert(pid >= 0);

        if (pid == 0)
                pid = getpid_cached();
        if (pid == 1) /* PID 1 has no parent, shortcut this case */
                return -EADDRNOTAVAIL;

        if (pid == getpid_cached()) {
                if (ret)
                        *ret = getppid();
                return 0;
        }

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

        /* If ppid is zero the process has no parent. Which might be the case for PID 1 (caught above)
         * but also for processes originating in other namespaces that are inserted into a pidns.
         * Return a recognizable error in this case. */
        if (ppid == 0)
                return -EADDRNOTAVAIL;

        if ((pid_t) ppid < 0 || (unsigned long) (pid_t) ppid != ppid)
                return -ERANGE;

        if (ret)
                *ret = (pid_t) ppid;

        return 0;
}

int pidref_get_ppid(const PidRef *pidref, pid_t *ret) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref_is_remote(pidref))
                return -EREMOTE;

        if (pidref->fd >= 0) {
                r = pidfd_get_ppid(pidref->fd, ret);
                if (!ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return r;
        }

        pid_t ppid;
        r = pid_get_ppid(pidref->pid, ret ? &ppid : NULL);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        if (ret)
                *ret = ppid;
        return 0;
}

int pidref_get_ppid_as_pidref(const PidRef *pidref, PidRef *ret) {
        pid_t ppid;
        int r;

        assert(ret);

        r = pidref_get_ppid(pidref, &ppid);
        if (r < 0)
                return r;

        for (unsigned attempt = 0; attempt < 16; attempt++) {
                _cleanup_(pidref_done) PidRef parent = PIDREF_NULL;

                r = pidref_set_pid(&parent, ppid);
                if (r < 0)
                        return r;

                /* If we have a pidfd of the original PID, let's verify that the process we acquired really
                 * is the parent still */
                if (pidref->fd >= 0) {
                        r = pidref_get_ppid(pidref, &ppid);
                        if (r < 0)
                                return r;

                        /* Did the PPID change since we queried it? if so we might have pinned the wrong
                         * process, if its PID got reused by now. Let's try again */
                        if (parent.pid != ppid)
                                continue;
                }

                *ret = TAKE_PIDREF(parent);
                return 0;
        }

        /* Give up after 16 tries */
        return -ENOTRECOVERABLE;
}

int pid_get_start_time(pid_t pid, usec_t *ret) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(pid >= 0);

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

        unsigned long llu;

        if (sscanf(p, " "
                   "%*c " /* state */
                   "%*u " /* ppid */
                   "%*u " /* pgrp */
                   "%*u " /* session */
                   "%*u " /* tty_nr */
                   "%*u " /* tpgid */
                   "%*u " /* flags */
                   "%*u " /* minflt */
                   "%*u " /* cminflt */
                   "%*u " /* majflt */
                   "%*u " /* cmajflt */
                   "%*u " /* utime */
                   "%*u " /* stime */
                   "%*u " /* cutime */
                   "%*u " /* cstime */
                   "%*i " /* priority */
                   "%*i " /* nice */
                   "%*u " /* num_threads */
                   "%*u " /* itrealvalue */
                   "%lu ", /* starttime */
                   &llu) != 1)
                return -EIO;

        if (ret)
                *ret = jiffies_to_usec(llu); /* CLOCK_BOOTTIME */

        return 0;
}

int pidref_get_start_time(const PidRef *pid, usec_t *ret) {
        usec_t t;
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        r = pid_get_start_time(pid->pid, ret ? &t : NULL);
        if (r < 0)
                return r;

        r = pidref_verify(pid);
        if (r < 0)
                return r;

        if (ret)
                *ret = t;

        return 0;
}

int get_process_umask(pid_t pid, mode_t *ret) {
        _cleanup_free_ char *m = NULL;
        int r;

        assert(pid >= 0);
        assert(ret);

        r = procfs_file_get_field(pid, "status", "Umask", &m);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        return parse_mode(m, ret);
}

int wait_for_terminate(pid_t pid, siginfo_t *ret) {
        return pidref_wait_for_terminate(&PIDREF_MAKE_FROM_PID(pid), ret);
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
int pidref_wait_for_terminate_and_check(const char *name, PidRef *pidref, WaitFlags flags) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;
        if (pidref->pid == 1 || pidref_is_self(pidref))
                return -ECHILD;

        _cleanup_free_ char *buffer = NULL;
        if (!name) {
                r = pidref_get_comm(pidref, &buffer);
                if (r < 0)
                        log_debug_errno(r, "Failed to acquire process name of " PID_FMT ", ignoring: %m", pidref->pid);
                else
                        name = buffer;
        }

        int prio = flags & WAIT_LOG_ABNORMAL ? LOG_ERR : LOG_DEBUG;

        siginfo_t status;
        r = pidref_wait_for_terminate(pidref, &status);
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

int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags) {
        return pidref_wait_for_terminate_and_check(name, &PIDREF_MAKE_FROM_PID(pid), flags);
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

void sigkill_nowait(pid_t pid) {
        assert(pid > 1);

        (void) kill(pid, SIGKILL);
}

void sigkill_nowaitp(pid_t *pid) {
        PROTECT_ERRNO;

        if (!pid)
                return;
        if (*pid <= 1)
                return;

        sigkill_nowait(*pid);
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
        const char *path;
        size_t sum = 0;
        int r;

        assert(pid >= 0);
        assert(field);
        assert(ret);

        if (pid == 0 || pid == getpid_cached())
                return strdup_to_full(ret, getenv(field));

        if (!pid_is_valid(pid))
                return -EINVAL;

        path = procfs_file_alloca(pid, "environ");

        r = fopen_unlocked(path, "re", &f);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *match;

                if (sum > ENVIRONMENT_BLOCK_MAX) /* Give up searching eventually */
                        return -ENOBUFS;

                r = read_nul_string(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)  /* EOF */
                        break;

                sum += r;

                match = startswith(line, field);
                if (match && *match == '=')
                        return strdup_to_full(ret, match + 1);
        }

        *ret = NULL;
        return 0;
}

int pidref_is_my_child(PidRef *pid) {
        int r;

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        if (pid->pid == 1 || pidref_is_self(pid))
                return false;

        pid_t ppid;
        r = pidref_get_ppid(pid, &ppid);
        if (r == -EADDRNOTAVAIL) /* if this process is outside of our pidns, it is definitely not our child */
                return false;
        if (r < 0)
                return r;

        return ppid == getpid_cached();
}

int pid_is_my_child(pid_t pid) {

        if (pid == 0)
                return false;

        return pidref_is_my_child(&PIDREF_MAKE_FROM_PID(pid));
}

int pidref_is_unwaited(PidRef *pid) {
        int r;

        /* Checks whether a PID is still valid at all, including a zombie */

        if (!pidref_is_set(pid))
                return -ESRCH;

        if (pidref_is_remote(pid))
                return -EREMOTE;

        if (pid->pid == 1 || pidref_is_self(pid))
                return true;

        r = pidref_kill(pid, 0);
        if (r == -ESRCH)
                return false;
        if (r < 0)
                return r;

        return true;
}

int pid_is_unwaited(pid_t pid) {

        if (pid == 0)
                return true;

        return pidref_is_unwaited(&PIDREF_MAKE_FROM_PID(pid));
}

int pid_is_alive(pid_t pid) {
        int r;

        /* Checks whether a PID is still valid and not a zombie */

        if (pid < 0)
                return -ESRCH;

        if (pid <= 1) /* If we or PID 1 would be a zombie, this code would not be running */
                return true;

        if (pid == getpid_cached())
                return true;

        r = get_process_state(pid);
        if (r == -ESRCH)
                return false;
        if (r < 0)
                return r;

        return r != 'Z';
}

int pidref_is_alive(const PidRef *pidref) {
        int r, result;

        if (!pidref_is_set(pidref))
                return -ESRCH;

        if (pidref_is_remote(pidref))
                return -EREMOTE;

        result = pid_is_alive(pidref->pid);
        if (result < 0) {
                assert(result != -ESRCH);
                return result;
        }

        r = pidref_verify(pidref);
        if (r == -ESRCH)
                return false;
        if (r < 0)
                return r;

        return result;
}

int pidref_from_same_root_fs(PidRef *a, PidRef *b) {
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        int r;

        /* Checks if the two specified processes have the same root fs. Either can be specified as NULL in
         * which case we'll check against ourselves. */

        if (!a || !b) {
                r = pidref_set_self(&self);
                if (r < 0)
                        return r;
                if (!a)
                        a = &self;
                if (!b)
                        b = &self;
        }

        if (!pidref_is_set(a) || !pidref_is_set(b))
                return -ESRCH;

        /* If one of the two processes have the same root they cannot have the same root fs, but if both of
         * them do we don't know */
        if (pidref_is_remote(a) && pidref_is_remote(b))
                return -EREMOTE;
        if (pidref_is_remote(a) || pidref_is_remote(b))
                return false;

        if (pidref_equal(a, b))
                return true;

        const char *roota = procfs_file_alloca(a->pid, "root");
        const char *rootb = procfs_file_alloca(b->pid, "root");

        int result = inode_same(roota, rootb, 0);
        if (result == -ENOENT)
                return proc_mounted() == 0 ? -ENOSYS : -ESRCH;
        if (result < 0)
                return result;

        r = pidref_verify(a);
        if (r < 0)
                return r;
        r = pidref_verify(b);
        if (r < 0)
                return r;

        return result;
}

bool is_main_thread(void) {
        static thread_local int cached = -1;

        if (cached < 0)
                cached = getpid_cached() == gettid();

        return cached;
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

        if (((unsigned long) current & OPINIONATED_PERSONALITY_MASK) == PER_LINUX32)
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
                        log_struct_errno(
                                LOG_EMERG, errno,
                                LOG_MESSAGE_ID(SD_MESSAGE_VALGRIND_HELPER_FORK_STR),
                                LOG_MESSAGE("Failed to fork off valgrind helper: %m"));
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

bool nice_is_valid(int n) {
        return n >= PRIO_MIN && n < PRIO_MAX;
}

bool sched_policy_is_valid(int i) {
        return IN_SET(i, SCHED_OTHER, SCHED_BATCH, SCHED_IDLE, SCHED_FIFO, SCHED_RR);
}

bool sched_priority_is_valid(int i) {
        return i >= 0 && i <= sched_get_priority_max(SCHED_RR);
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

        (void) __atomic_compare_exchange_n(
                        &cached_pid,
                        &current_value,
                        CACHED_PID_BUSY,
                        false,
                        __ATOMIC_SEQ_CST,
                        __ATOMIC_SEQ_CST);

        switch (current_value) {

        case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
                pid_t new_pid;

                new_pid = getpid();

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
                return getpid();

        default: /* Properly initialized */
                return current_value;
        }
}

int must_be_root(void) {

        if (geteuid() == 0)
                return 0;

        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be root.");
}

pid_t clone_with_nested_stack(int (*fn)(void *), int flags, void *userdata) {
        size_t ps;
        pid_t pid;
        void *mystack;

        /* A wrapper around glibc's clone() call that automatically sets up a "nested" stack. Only supports
         * invocations without CLONE_VM, so that we can continue to use the parent's stack mapping.
         *
         * Note: glibc's clone() wrapper does not synchronize malloc() locks. This means that if the parent
         * is threaded these locks will be in an undefined state in the child, and hence memory allocations
         * are likely going to run into deadlocks. Hence: if you use this function make sure your parent is
         * strictly single-threaded or your child never calls malloc(). */

        assert((flags & (CLONE_VM|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|
                         CLONE_CHILD_CLEARTID|CLONE_SETTLS)) == 0);

        /* We allocate some space on the stack to use as the stack for the child (hence "nested"). Note that
         * the net effect is that the child will have the start of its stack inside the stack of the parent,
         * but since they are a CoW copy of each other that's fine. We allocate one page-aligned page. But
         * since we don't want to deal with differences between systems where the stack grows backwards or
         * forwards we'll allocate one more and place the stack address in the middle. Except that we also
         * want it page aligned, hence we'll allocate one page more. Makes 3. */

        ps = page_size();
        mystack = alloca(ps*3);
        mystack = (uint8_t*) mystack + ps; /* move pointer one page ahead since stacks usually grow backwards */
        mystack = (void*) ALIGN_TO((uintptr_t) mystack, ps); /* align to page size (moving things further ahead) */

#if HAVE_CLONE
        pid = clone(fn, mystack, flags, userdata);
#else
        pid = __clone2(fn, mystack, ps, flags, userdata);
#endif
        if (pid < 0)
                return -errno;

        return pid;
}

static void restore_sigsetp(sigset_t **ssp) {
        if (*ssp)
                (void) sigprocmask(SIG_SETMASK, *ssp, NULL);
}

static int fork_flags_to_signal(ForkFlags flags) {
        return (flags & FORK_DEATHSIG_SIGTERM) ? SIGTERM :
                (flags & FORK_DEATHSIG_SIGINT) ? SIGINT :
                                                 SIGKILL;
}

int pidref_safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                PidRef *ret_pid) {

        pid_t original_pid, pid;
        sigset_t saved_ss, ss;
        _unused_ _cleanup_(restore_sigsetp) sigset_t *saved_ssp = NULL;
        bool block_signals = false, block_all = false, intermediary = false;
        _cleanup_close_pair_ int pidref_transport_fds[2] = EBADF_PAIR;
        int prio, r;

        assert(!FLAGS_SET(flags, FORK_WAIT|FORK_FREEZE));
        assert(!FLAGS_SET(flags, FORK_DETACH) ||
               (flags & (FORK_WAIT|FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGINT|FORK_DEATHSIG_SIGKILL)) == 0);

        /* A wrapper around fork(), that does a couple of important initializations in addition to mere
         * forking. If provided, ret_pid is initialized in both the parent and the child process, both times
         * referencing the child process. Returns == 0 in the child and > 0 in the parent. */

        prio = flags & FORK_LOG ? LOG_ERR : LOG_DEBUG;

        original_pid = getpid_cached();

        if (flags & FORK_FLUSH_STDIO) {
                fflush(stdout);
                fflush(stderr); /* This one shouldn't be necessary, stderr should be unbuffered anyway, but let's better be safe than sorry */
        }

        if (flags & (FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGINT)) {
                /* We temporarily block all signals, so that the new child has them blocked initially. This
                 * way, we can be sure that SIGTERMs are not lost we might send to the child. (Note that for
                 * FORK_DEATHSIG_SIGKILL we don't bother, since it cannot be blocked anyway.) */

                assert_se(sigfillset(&ss) >= 0);
                block_signals = block_all = true;

        } else if (flags & FORK_WAIT) {
                /* Let's block SIGCHLD at least, so that we can safely watch for the child process */

                assert_se(sigemptyset(&ss) >= 0);
                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                block_signals = true;
        }

        if (block_signals) {
                if (sigprocmask(SIG_BLOCK, &ss, &saved_ss) < 0)
                        return log_full_errno(prio, errno, "Failed to block signal mask: %m");
                saved_ssp = &saved_ss;
        }

        if (FLAGS_SET(flags, FORK_DETACH)) {
                /* Fork off intermediary child if needed */

                r = is_reaper_process();
                if (r < 0)
                        return log_full_errno(prio, r, "Failed to determine if we are a reaper process: %m");

                if (!r) {
                        /* Not a reaper process, hence do a double fork() so we are reparented to one */

                        if (ret_pid && socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pidref_transport_fds) < 0)
                                return log_full_errno(prio, errno, "Failed to allocate pidref socket: %m");

                        pid = fork();
                        if (pid < 0)
                                return log_full_errno(prio, errno, "Failed to fork off '%s': %m", strna(name));
                        if (pid > 0) {
                                log_debug("Successfully forked off intermediary '%s' as PID " PID_FMT ".", strna(name), pid);

                                pidref_transport_fds[1] = safe_close(pidref_transport_fds[1]);

                                if (pidref_transport_fds[0] >= 0) {
                                        /* Wait for the intermediary child to exit so the caller can be certain the actual child
                                         * process has been reparented by the time this function returns. */
                                        r = wait_for_terminate_and_check(name, pid, FLAGS_SET(flags, FORK_LOG) ? WAIT_LOG : 0);
                                        if (r < 0)
                                                return log_full_errno(prio, r, "Failed to wait for intermediary process: %m");
                                        if (r != EXIT_SUCCESS) /* exit status > 0 should be treated as failure, too */
                                                return -EPROTO;

                                        int pidfd;
                                        ssize_t n = receive_one_fd_iov(
                                                        pidref_transport_fds[0],
                                                        &IOVEC_MAKE(&pid, sizeof(pid)),
                                                        /* iovlen= */ 1,
                                                        /* flags= */ 0,
                                                        &pidfd);
                                        if (n < 0)
                                                return log_full_errno(prio, n, "Failed to receive child pidref: %m");

                                        *ret_pid = (PidRef) { .pid = pid, .fd = pidfd };
                                }

                                return 1; /* return in the parent */
                        }

                        pidref_transport_fds[0] = safe_close(pidref_transport_fds[0]);
                        intermediary = true;
                }
        }

        if ((flags & (FORK_NEW_MOUNTNS|FORK_NEW_USERNS|FORK_NEW_NETNS|FORK_NEW_PIDNS)) != 0)
                pid = raw_clone(SIGCHLD|
                                (FLAGS_SET(flags, FORK_NEW_MOUNTNS) ? CLONE_NEWNS : 0) |
                                (FLAGS_SET(flags, FORK_NEW_USERNS) ? CLONE_NEWUSER : 0) |
                                (FLAGS_SET(flags, FORK_NEW_NETNS) ? CLONE_NEWNET : 0) |
                                (FLAGS_SET(flags, FORK_NEW_PIDNS) ? CLONE_NEWPID : 0));
        else
                pid = fork();
        if (pid < 0)
                return log_full_errno(prio, errno, "Failed to fork off '%s': %m", strna(name));
        if (pid > 0) {

                /* If we are in the intermediary process, exit now */
                if (intermediary) {
                        if (pidref_transport_fds[1] >= 0) {
                                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                                r = pidref_set_pid(&pidref, pid);
                                if (r < 0) {
                                        log_full_errno(prio, r, "Failed to open reference to PID "PID_FMT": %m", pid);
                                        _exit(EXIT_FAILURE);
                                }

                                r = send_one_fd_iov(
                                                pidref_transport_fds[1],
                                                pidref.fd,
                                                &IOVEC_MAKE(&pidref.pid, sizeof(pidref.pid)),
                                                /* iovlen= */ 1,
                                                /* flags= */ 0);
                                if (r < 0) {
                                        log_full_errno(prio, r, "Failed to send child pidref: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        _exit(EXIT_SUCCESS);
                }

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

                        /* If we are in the parent and successfully waited, then the process doesn't exist anymore. */
                        if (ret_pid)
                                *ret_pid = PIDREF_NULL;

                        return 1;
                }

                if (ret_pid) {
                        if (FLAGS_SET(flags, FORK_PID_ONLY))
                                *ret_pid = PIDREF_MAKE_FROM_PID(pid);
                        else {
                                r = pidref_set_pid(ret_pid, pid);
                                if (r < 0) /* Let's not fail for this, no matter what, the process exists after all, and that's key */
                                        *ret_pid = PIDREF_MAKE_FROM_PID(pid);
                        }
                }

                return 1;
        }

        /* We are in the child process */

        pidref_transport_fds[1] = safe_close(pidref_transport_fds[1]);

        /* Restore signal mask manually */
        saved_ssp = NULL;

        if (flags & FORK_REOPEN_LOG) {
                /* Close the logs if requested, before we log anything. And make sure we reopen it if needed. */
                log_close();
                log_set_open_when_needed(true);
                log_settle_target();
        }

        if (name) {
                r = rename_process(name);
                if (r < 0)
                        log_full_errno(flags & FORK_LOG ? LOG_WARNING : LOG_DEBUG,
                                       r, "Failed to rename process, ignoring: %m");
        }

        if (flags & (FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGINT|FORK_DEATHSIG_SIGKILL))
                if (prctl(PR_SET_PDEATHSIG, fork_flags_to_signal(flags)) < 0) {
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

        if (flags & (FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGKILL|FORK_DEATHSIG_SIGINT)) {
                pid_t ppid;
                /* Let's see if the parent PID is still the one we started from? If not, then the parent
                 * already died by the time we set PR_SET_PDEATHSIG, hence let's emulate the effect */

                ppid = getppid();
                if (ppid == 0)
                        /* Parent is in a different PID namespace. */;
                else if (ppid != original_pid) {
                        int sig = fork_flags_to_signal(flags);
                        log_debug("Parent died early, raising %s.", signal_to_string(sig));
                        (void) raise(sig);
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

        if (FLAGS_SET(flags, FORK_PRIVATE_TMP)) {
                assert(FLAGS_SET(flags, FORK_NEW_MOUNTNS));

                /* Optionally, overmount new tmpfs instance on /tmp/. */
                r = mount_nofollow("tmpfs", "/tmp", "tmpfs",
                                   MS_NOSUID|MS_NODEV,
                                   "mode=01777" TMPFS_LIMITS_RUN);
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to overmount /tmp/: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_REARRANGE_STDIO) {
                if (stdio_fds) {
                        r = rearrange_stdio(stdio_fds[0], stdio_fds[1], stdio_fds[2]);
                        if (r < 0) {
                                log_full_errno(prio, r, "Failed to rearrange stdio fds: %m");
                                _exit(EXIT_FAILURE);
                        }

                        /* Turn off O_NONBLOCK on the fdio fds, in case it was left on */
                        stdio_disable_nonblock();
                } else {
                        r = make_null_stdio();
                        if (r < 0) {
                                log_full_errno(prio, r, "Failed to connect stdin/stdout to /dev/null: %m");
                                _exit(EXIT_FAILURE);
                        }
                }
        } else if (flags & FORK_STDOUT_TO_STDERR) {
                if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
                        log_full_errno(prio, errno, "Failed to connect stdout to stderr: %m");
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

        if (flags & FORK_PACK_FDS) {
                /* FORK_CLOSE_ALL_FDS ensures that except_fds are the only FDs >= 3 that are
                 * open, this is including the log. This is required by pack_fds, which will
                 * get stuck in an infinite loop of any FDs other than except_fds are open. */
                assert(FLAGS_SET(flags, FORK_CLOSE_ALL_FDS));

                r = pack_fds(except_fds, n_except_fds);
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to pack file descriptors: %m");
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

        if (flags & FORK_RLIMIT_NOFILE_SAFE) {
                r = rlimit_nofile_safe();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to lower RLIMIT_NOFILE's soft limit to 1K: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (!FLAGS_SET(flags, FORK_KEEP_NOTIFY_SOCKET)) {
                r = RET_NERRNO(unsetenv("NOTIFY_SOCKET"));
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to unset $NOTIFY_SOCKET: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (FLAGS_SET(flags, FORK_FREEZE))
                freeze();

        if (ret_pid) {
                if (FLAGS_SET(flags, FORK_PID_ONLY))
                        *ret_pid = PIDREF_MAKE_FROM_PID(getpid_cached());
                else {
                        r = pidref_set_self(ret_pid);
                        if (r < 0) {
                                log_full_errno(prio, r, "Failed to acquire PID reference on ourselves: %m");
                                _exit(EXIT_FAILURE);
                        }
                }
        }

        return 0;
}

int safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid) {

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r;

        /* Getting the detached child process pid without pidfd is racy, so don't allow it if not returning
         * a pidref to the caller. */
        assert(!FLAGS_SET(flags, FORK_DETACH) || !ret_pid);

        r = pidref_safe_fork_full(name, stdio_fds, except_fds, n_except_fds, flags|FORK_PID_ONLY, ret_pid ? &pidref : NULL);
        if (r < 0 || !ret_pid)
                return r;

        *ret_pid = pidref.pid;

        return r;
}

int namespace_fork(
                const char *outer_name,
                const char *inner_name,
                int except_fds[],
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

        r = safe_fork_full(outer_name,
                           NULL,
                           except_fds, n_except_fds,
                           (flags|FORK_DEATHSIG_SIGINT|FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGKILL) & ~(FORK_REOPEN_LOG|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE), ret_pid);
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
                r = safe_fork_full(inner_name,
                                   NULL,
                                   except_fds, n_except_fds,
                                   flags & ~(FORK_WAIT|FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO), &pid);
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

        if (!oom_score_adjust_is_valid(value))
                return -EINVAL;

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

        r = safe_atoi(t, &a);
        if (r < 0)
                return r;

        if (!oom_score_adjust_is_valid(a))
                return -ENODATA;

        if (ret)
                *ret = a;

        return 0;
}

static int rlimit_to_nice(rlim_t limit) {
        if (limit <= 1)
                return PRIO_MAX-1; /* i.e. 19 */

        if (limit >= -PRIO_MIN + PRIO_MAX)
                return PRIO_MIN; /* i.e. -20 */

        return PRIO_MAX - (int) limit;
}

int setpriority_closest(int priority) {
        struct rlimit highest;
        int r, current, limit;

        /* Try to set requested nice level */
        r = RET_NERRNO(setpriority(PRIO_PROCESS, 0, priority));
        if (r >= 0)
                return 1;
        if (!ERRNO_IS_NEG_PRIVILEGE(r))
                return r;

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
                return r;

        if (getrlimit(RLIMIT_NICE, &highest) < 0)
                return -errno;

        limit = rlimit_to_nice(highest.rlim_cur);

        /* Push to the allowed limit if we're higher than that. Note that we could also be less nice than
         * limit allows us, but still higher than what's requested. In that case our current value is
         * the best choice. */
        if (current > limit)
                if (setpriority(PRIO_PROCESS, 0, limit) < 0)
                        return -errno;

        log_debug("Cannot set requested nice level (%i), using next best (%i).", priority, MIN(current, limit));
        return 0;
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

        /* waitid() failed with an ECHLD error (because there are no left-over child processes) or any other
         * (unexpected) error. Freeze for good now! */
        for (;;)
                pause();
}

int get_process_threads(pid_t pid) {
        _cleanup_free_ char *t = NULL;
        int n, r;

        if (pid < 0)
                return -EINVAL;

        r = procfs_file_get_field(pid, "status", "Threads", &t);
        if (r == -ENOENT)
                return -ESRCH;
        if (r < 0)
                return r;

        r = safe_atoi(t, &n);
        if (r < 0)
                return r;
        if (n < 0)
                return -EINVAL;

        return n;
}

int is_reaper_process(void) {
        int b = 0;

        /* Checks if we are running in a reaper process, i.e. if we are expected to deal with processes
         * reparented to us. This simply checks if we are PID 1 or if PR_SET_CHILD_SUBREAPER was called. */

        if (getpid_cached() == 1)
                return true;

        if (prctl(PR_GET_CHILD_SUBREAPER, (unsigned long) &b, 0UL, 0UL, 0UL) < 0)
                return -errno;

        return b != 0;
}

int make_reaper_process(bool b) {

        if (getpid_cached() == 1) {

                if (!b)
                        return -EINVAL;

                return 0;
        }

        /* Some prctl()s insist that all 5 arguments are specified, others do not. Let's always specify all,
         * to avoid any ambiguities */
        if (prctl(PR_SET_CHILD_SUBREAPER, (unsigned long) b, 0UL, 0UL, 0UL) < 0)
                return -errno;

        return 0;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(posix_spawnattr_t*, posix_spawnattr_destroy, NULL);

int posix_spawn_wrapper(
                const char *path,
                char * const *argv,
                char * const *envp,
                const char *cgroup,
                PidRef *ret_pidref) {

        short flags = POSIX_SPAWN_SETSIGMASK;
        posix_spawnattr_t attr;
        sigset_t mask;
        int r;

        /* Forks and invokes 'path' with 'argv' and 'envp' using CLONE_VM and CLONE_VFORK, which means the
         * caller will be blocked until the child either exits or exec's. The memory of the child will be
         * fully shared with the memory of the parent, so that there are no copy-on-write or memory.max
         * issues.
         *
         * Also, move the newly-created process into 'cgroup' through POSIX_SPAWN_SETCGROUP (clone3())
         * if available.
         * returns 1: We're already in the right cgroup
         *         0: 'cgroup' not specified or POSIX_SPAWN_SETCGROUP is not supported. The caller
         *            needs to call 'cg_attach' on their own */

        assert(path);
        assert(argv);
        assert(ret_pidref);

        assert_se(sigfillset(&mask) >= 0);

        r = posix_spawnattr_init(&attr);
        if (r != 0)
                return -r; /* These functions return a positive errno on failure */

        /* Initialization needs to succeed before we can set up a destructor. */
        _unused_ _cleanup_(posix_spawnattr_destroyp) posix_spawnattr_t *attr_destructor = &attr;

#if HAVE_PIDFD_SPAWN
        static bool have_clone_into_cgroup = true; /* kernel 5.7+ */
        _cleanup_close_ int cgroup_fd = -EBADF;

        if (cgroup && have_clone_into_cgroup) {
                _cleanup_free_ char *resolved_cgroup = NULL;

                r = cg_get_path(SYSTEMD_CGROUP_CONTROLLER, cgroup, /* suffix= */ NULL, &resolved_cgroup);
                if (r < 0)
                        return r;

                cgroup_fd = open(resolved_cgroup, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (cgroup_fd < 0)
                        return -errno;

                r = posix_spawnattr_setcgroup_np(&attr, cgroup_fd);
                if (r != 0)
                        return -r;

                flags |= POSIX_SPAWN_SETCGROUP;
        }
#endif

        r = posix_spawnattr_setflags(&attr, flags);
        if (r != 0)
                return -r;
        r = posix_spawnattr_setsigmask(&attr, &mask);
        if (r != 0)
                return -r;

#if HAVE_PIDFD_SPAWN
        _cleanup_close_ int pidfd = -EBADF;

        r = pidfd_spawn(&pidfd, path, NULL, &attr, argv, envp);
        if (ERRNO_IS_NOT_SUPPORTED(r) && FLAGS_SET(flags, POSIX_SPAWN_SETCGROUP) && cg_is_threaded(cgroup) > 0)
                return -EUCLEAN; /* clone3() could also return EOPNOTSUPP if the target cgroup is in threaded mode,
                                    turn that into something recognizable */
        if ((ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || r == E2BIG) &&
            FLAGS_SET(flags, POSIX_SPAWN_SETCGROUP)) {
                /* Compiled on a newer host, or seccomp&friends blocking clone3()? Fallback, but
                 * need to disable POSIX_SPAWN_SETCGROUP, which is what redirects to clone3().
                 * Note that we might get E2BIG here since some kernels (e.g. 5.4) support clone3()
                 * but not CLONE_INTO_CGROUP. */

                /* CLONE_INTO_CGROUP definitely won't work, hence remember the fact so that we don't
                 * retry every time. */
                have_clone_into_cgroup = false;

                flags &= ~POSIX_SPAWN_SETCGROUP;
                r = posix_spawnattr_setflags(&attr, flags);
                if (r != 0)
                        return -r;

                r = pidfd_spawn(&pidfd, path, NULL, &attr, argv, envp);
        }
        if (r != 0)
                return -r;

        r = pidref_set_pidfd_consume(ret_pidref, TAKE_FD(pidfd));
        if (r < 0)
                return r;

        return FLAGS_SET(flags, POSIX_SPAWN_SETCGROUP);
#else
        pid_t pid;

        r = posix_spawn(&pid, path, NULL, &attr, argv, envp);
        if (r != 0)
                return -r;

        r = pidref_set_pid(ret_pidref, pid);
        if (r < 0)
                return r;

        return 0; /* We did not use CLONE_INTO_CGROUP so return 0, the caller will have to move the child */
#endif
}

int proc_dir_open(DIR **ret) {
        DIR *d;

        assert(ret);

        d = opendir("/proc");
        if (!d)
                return -errno;

        *ret = d;
        return 0;
}

int proc_dir_read(DIR *d, pid_t *ret) {
        assert(d);

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                return -errno;

                        break;
                }

                if (!IN_SET(de->d_type, DT_DIR, DT_UNKNOWN))
                        continue;

                if (parse_pid(de->d_name, ret) >= 0)
                        return 1;
        }

        if (ret)
                *ret = 0;
        return 0;
}

int proc_dir_read_pidref(DIR *d, PidRef *ret) {
        int r;

        assert(d);

        for (;;) {
                pid_t pid;

                r = proc_dir_read(d, &pid);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = pidref_set_pid(ret, pid);
                if (r == -ESRCH) /* gone by now? skip it */
                        continue;
                if (r < 0)
                        return r;

                return 1;
        }

        if (ret)
                *ret = PIDREF_NULL;
        return 0;
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

_noreturn_ void report_errno_and_exit(int errno_fd, int error) {
        int r;

        if (error >= 0)
                _exit(EXIT_SUCCESS);

        assert(errno_fd >= 0);

        r = loop_write(errno_fd, &error, sizeof(error));
        if (r < 0)
                log_debug_errno(r, "Failed to write errno to errno_fd=%d: %m", errno_fd);

        _exit(EXIT_FAILURE);
}

int read_errno(int errno_fd) {
        int r;

        assert(errno_fd >= 0);

        /* The issue here is that it's impossible to distinguish between an error code returned by child and
         * IO error arose when reading it. So, the function logs errors and return EIO for the later case. */

        ssize_t n = loop_read(errno_fd, &r, sizeof(r), /* do_poll = */ false);
        if (n < 0) {
                log_debug_errno(n, "Failed to read errno: %m");
                return -EIO;
        }
        if (n == sizeof(r)) {
                if (r == 0)
                        return 0;
                if (r < 0) /* child process reported an error, return it */
                        return log_debug_errno(r, "Child process failed with errno: %m");
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Received an errno, but it's a positive value.");
        }
        if (n != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Received unexpected amount of bytes while reading errno.");

        /* the process exited without reporting an error, assuming success */
        return 0;
}
