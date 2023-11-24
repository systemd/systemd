/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "format-util.h"
#include "macro.h"
#include "namespace-util.h"
#include "time-util.h"

#define procfs_file_alloca(pid, field)                                  \
        ({                                                              \
                pid_t _pid_ = (pid);                                    \
                const char *_field_ = (field);                          \
                char *_r_;                                              \
                if (_pid_ == 0) {                                       \
                        _r_ = newa(char, STRLEN("/proc/self/") + strlen(_field_) + 1); \
                        strcpy(stpcpy(_r_, "/proc/self/"), _field_);    \
                } else {                                                \
                        _r_ = newa(char, STRLEN("/proc/") + DECIMAL_STR_MAX(pid_t) + 1 + strlen(_field_) + 1); \
                        sprintf(_r_, "/proc/" PID_FMT "/%s", _pid_, _field_); \
                }                                                       \
                (const char*) _r_;                                      \
        })

typedef enum ProcessCmdlineFlags {
        PROCESS_CMDLINE_COMM_FALLBACK = 1 << 0,
        PROCESS_CMDLINE_USE_LOCALE    = 1 << 1,
        PROCESS_CMDLINE_QUOTE         = 1 << 2,
        PROCESS_CMDLINE_QUOTE_POSIX   = 1 << 3,
} ProcessCmdlineFlags;

int pid_get_comm(pid_t pid, char **ret);
int pidref_get_comm(const PidRef *pid, char **ret);
int pid_get_cmdline(pid_t pid, size_t max_columns, ProcessCmdlineFlags flags, char **ret);
int pidref_get_cmdline(const PidRef *pid, size_t max_columns, ProcessCmdlineFlags flags, char **ret);
int pid_get_cmdline_strv(pid_t pid, ProcessCmdlineFlags flags, char ***ret);
int pidref_get_cmdline_strv(const PidRef *pid, ProcessCmdlineFlags flags, char ***ret);
int get_process_exe(pid_t pid, char **ret);
int pid_get_uid(pid_t pid, uid_t *ret);
int pidref_get_uid(const PidRef *pid, uid_t *ret);
int get_process_gid(pid_t pid, gid_t *ret);
int get_process_capeff(pid_t pid, char **ret);
int get_process_cwd(pid_t pid, char **ret);
int get_process_root(pid_t pid, char **ret);
int get_process_environ(pid_t pid, char **ret);
int get_process_ppid(pid_t pid, pid_t *ret);
int pid_get_start_time(pid_t pid, uint64_t *ret);
int pidref_get_start_time(const PidRef* pid, uint64_t *ret);
int get_process_umask(pid_t pid, mode_t *ret);

int container_get_leader(const char *machine, pid_t *pid);

int namespace_get_leader(pid_t pid, NamespaceType type, pid_t *ret);

int wait_for_terminate(pid_t pid, siginfo_t *status);

typedef enum WaitFlags {
        WAIT_LOG_ABNORMAL             = 1 << 0,
        WAIT_LOG_NON_ZERO_EXIT_STATUS = 1 << 1,

        /* A shortcut for requesting the most complete logging */
        WAIT_LOG = WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS,
} WaitFlags;

int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags);
int wait_for_terminate_with_timeout(pid_t pid, usec_t timeout);

void sigkill_wait(pid_t pid);
void sigkill_waitp(pid_t *pid);
void sigterm_wait(pid_t pid);
void sigkill_nowait(pid_t pid);
void sigkill_nowaitp(pid_t *pid);

int kill_and_sigcont(pid_t pid, int sig);

int pid_is_kernel_thread(pid_t pid);
int pidref_is_kernel_thread(const PidRef *pid);

int getenv_for_pid(pid_t pid, const char *field, char **_value);

int pid_is_alive(pid_t pid);
int pidref_is_alive(const PidRef *pidref);
int pid_is_unwaited(pid_t pid);
int pidref_is_unwaited(const PidRef *pidref);
int pid_is_my_child(pid_t pid);
int pidref_is_my_child(const PidRef *pidref);
int pid_from_same_root_fs(pid_t pid);

bool is_main_thread(void);

bool oom_score_adjust_is_valid(int oa);

#ifndef PERSONALITY_INVALID
/* personality(7) documents that 0xffffffffUL is used for querying the
 * current personality, hence let's use that here as error
 * indicator. */
#define PERSONALITY_INVALID 0xffffffffLU
#endif

unsigned long personality_from_string(const char *p);
const char *personality_to_string(unsigned long);

int safe_personality(unsigned long p);
int opinionated_personality(unsigned long *ret);

const char *sigchld_code_to_string(int i) _const_;
int sigchld_code_from_string(const char *s) _pure_;

int sched_policy_to_string_alloc(int i, char **s);
int sched_policy_from_string(const char *s);

static inline pid_t PTR_TO_PID(const void *p) {
        return (pid_t) ((uintptr_t) p);
}

static inline void* PID_TO_PTR(pid_t pid) {
        return (void*) ((uintptr_t) pid);
}

void valgrind_summary_hack(void);

int pid_compare_func(const pid_t *a, const pid_t *b);

static inline bool nice_is_valid(int n) {
        return n >= PRIO_MIN && n < PRIO_MAX;
}

static inline bool sched_policy_is_valid(int i) {
        return IN_SET(i, SCHED_OTHER, SCHED_BATCH, SCHED_IDLE, SCHED_FIFO, SCHED_RR);
}

static inline bool sched_priority_is_valid(int i) {
        return i >= 0 && i <= sched_get_priority_max(SCHED_RR);
}

static inline bool pid_is_valid(pid_t p) {
        return p > 0;
}

pid_t getpid_cached(void);
void reset_cached_pid(void);

int must_be_root(void);

pid_t clone_with_nested_stack(int (*fn)(void *), int flags, void *userdata);

/* 💣 Note that FORK_NEW_USERNS + FORK_NEW_MOUNTNS should not be called in threaded programs, because they
 * cause us to use raw_clone() which does not synchronize the glibc malloc() locks, and thus will cause
 * deadlocks if the parent uses threads and the child does memory allocations. Hence: if the parent is
 * threaded these flags may not be used. These flags cannot be used if the parent uses threads or the child
 * uses malloc(). 💣 */
typedef enum ForkFlags {
        FORK_RESET_SIGNALS      = 1 <<  0, /* Reset all signal handlers and signal mask */
        FORK_CLOSE_ALL_FDS      = 1 <<  1, /* Close all open file descriptors in the child, except for 0,1,2 */
        FORK_DEATHSIG_SIGTERM   = 1 <<  2, /* Set PR_DEATHSIG in the child to SIGTERM */
        FORK_DEATHSIG_SIGINT    = 1 <<  3, /* Set PR_DEATHSIG in the child to SIGINT */
        FORK_DEATHSIG_SIGKILL   = 1 <<  4, /* Set PR_DEATHSIG in the child to SIGKILL */
        FORK_REARRANGE_STDIO    = 1 <<  5, /* Connect 0,1,2 to specified fds or /dev/null */
        FORK_REOPEN_LOG         = 1 <<  6, /* Reopen log connection */
        FORK_LOG                = 1 <<  7, /* Log above LOG_DEBUG log level about failures */
        FORK_WAIT               = 1 <<  8, /* Wait until child exited */
        FORK_NEW_MOUNTNS        = 1 <<  9, /* Run child in its own mount namespace                               💣 DO NOT USE IN THREADED PROGRAMS! 💣 */
        FORK_MOUNTNS_SLAVE      = 1 << 10, /* Make child's mount namespace MS_SLAVE */
        FORK_PRIVATE_TMP        = 1 << 11, /* Mount new /tmp/ in the child (combine with FORK_NEW_MOUNTNS!) */
        FORK_RLIMIT_NOFILE_SAFE = 1 << 12, /* Set RLIMIT_NOFILE soft limit to 1K for select() compat */
        FORK_STDOUT_TO_STDERR   = 1 << 13, /* Make stdout a copy of stderr */
        FORK_FLUSH_STDIO        = 1 << 14, /* fflush() stdout (and stderr) before forking */
        FORK_NEW_USERNS         = 1 << 15, /* Run child in its own user namespace                                💣 DO NOT USE IN THREADED PROGRAMS! 💣 */
        FORK_CLOEXEC_OFF        = 1 << 16, /* In the child: turn off O_CLOEXEC on all fds in except_fds[] */
        FORK_KEEP_NOTIFY_SOCKET = 1 << 17, /* Unless this specified, $NOTIFY_SOCKET will be unset. */
        FORK_DETACH             = 1 << 18, /* Double fork if needed to ensure PID1/subreaper is parent */
} ForkFlags;

int safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                const int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid);

static inline int safe_fork(const char *name, ForkFlags flags, pid_t *ret_pid) {
        return safe_fork_full(name, NULL, NULL, 0, flags, ret_pid);
}

int pidref_safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                const int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                PidRef *ret_pid);

static inline int pidref_safe_fork(const char *name, ForkFlags flags, PidRef *ret_pid) {
        return pidref_safe_fork_full(name, NULL, NULL, 0, flags, ret_pid);
}

int namespace_fork(const char *outer_name, const char *inner_name, const int except_fds[], size_t n_except_fds, ForkFlags flags, int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd, pid_t *ret_pid);

int set_oom_score_adjust(int value);
int get_oom_score_adjust(int *ret);

/* The highest possibly (theoretic) pid_t value on this architecture. */
#define PID_T_MAX ((pid_t) INT32_MAX)
/* The maximum number of concurrent processes Linux allows on this architecture, as well as the highest valid PID value
 * the kernel will potentially assign. This reflects a value compiled into the kernel (PID_MAX_LIMIT), and sets the
 * upper boundary on what may be written to the /proc/sys/kernel/pid_max sysctl (but do note that the sysctl is off by
 * 1, since PID 0 can never exist and there can hence only be one process less than the limit would suggest). Since
 * these values are documented in proc(5) we feel quite confident that they are stable enough for the near future at
 * least to define them here too. */
#define TASKS_MAX 4194303U

assert_cc(TASKS_MAX <= (unsigned long) PID_T_MAX);

/* Like TAKE_PTR() but for pid_t, resetting them to 0 */
#define TAKE_PID(pid) TAKE_GENERIC(pid, pid_t, 0)

int pidfd_get_pid(int fd, pid_t *ret);
int pidfd_verify_pid(int pidfd, pid_t pid);

int setpriority_closest(int priority);

_noreturn_ void freeze(void);

int get_process_threads(pid_t pid);

int is_reaper_process(void);
int make_reaper_process(bool b);

int posix_spawn_wrapper(const char *path, char *const *argv, char *const *envp, pid_t *ret_pid);

int proc_dir_open(DIR **ret);
int proc_dir_read(DIR *d, pid_t *ret);
int proc_dir_read_pidref(DIR *d, PidRef *ret);
