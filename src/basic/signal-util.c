/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>

#include "errno-util.h"
#include "macro.h"
#include "missing_syscall.h"
#include "missing_threads.h"
#include "parse-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"

int reset_all_signal_handlers(void) {
        static const struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_RESTART,
        };
        int r = 0;

        for (int sig = 1; sig < _NSIG; sig++) {

                /* These two cannot be caught... */
                if (IN_SET(sig, SIGKILL, SIGSTOP))
                        continue;

                /* On Linux the first two RT signals are reserved by
                 * glibc, and sigaction() will return EINVAL for them. */
                if (sigaction(sig, &sa, NULL) < 0)
                        if (errno != EINVAL && r >= 0)
                                r = -errno;
        }

        return r;
}

int reset_signal_mask(void) {
        sigset_t ss;

        if (sigemptyset(&ss) < 0)
                return -errno;

        return RET_NERRNO(sigprocmask(SIG_SETMASK, &ss, NULL));
}

int sigaction_many_internal(const struct sigaction *sa, ...) {
        int sig, r = 0;
        va_list ap;

        va_start(ap, sa);

        /* negative signal ends the list. 0 signal is skipped. */
        while ((sig = va_arg(ap, int)) >= 0) {

                if (sig == 0)
                        continue;

                if (sigaction(sig, sa, NULL) < 0) {
                        if (r >= 0)
                                r = -errno;
                }
        }

        va_end(ap);

        return r;
}

static int sigset_add_many_ap(sigset_t *ss, va_list ap) {
        int sig, r = 0;

        assert(ss);

        while ((sig = va_arg(ap, int)) >= 0) {

                if (sig == 0)
                        continue;

                if (sigaddset(ss, sig) < 0) {
                        if (r >= 0)
                                r = -errno;
                }
        }

        return r;
}

int sigset_add_many(sigset_t *ss, ...) {
        va_list ap;
        int r;

        va_start(ap, ss);
        r = sigset_add_many_ap(ss, ap);
        va_end(ap);

        return r;
}

int sigprocmask_many(int how, sigset_t *old, ...) {
        va_list ap;
        sigset_t ss;
        int r;

        if (sigemptyset(&ss) < 0)
                return -errno;

        va_start(ap, old);
        r = sigset_add_many_ap(&ss, ap);
        va_end(ap);

        if (r < 0)
                return r;

        if (sigprocmask(how, &ss, old) < 0)
                return -errno;

        return 0;
}

static const char *const static_signal_table[] = {
        [SIGHUP]    = "HUP",
        [SIGINT]    = "INT",
        [SIGQUIT]   = "QUIT",
        [SIGILL]    = "ILL",
        [SIGTRAP]   = "TRAP",
        [SIGABRT]   = "ABRT",
        [SIGBUS]    = "BUS",
        [SIGFPE]    = "FPE",
        [SIGKILL]   = "KILL",
        [SIGUSR1]   = "USR1",
        [SIGSEGV]   = "SEGV",
        [SIGUSR2]   = "USR2",
        [SIGPIPE]   = "PIPE",
        [SIGALRM]   = "ALRM",
        [SIGTERM]   = "TERM",
#ifdef SIGSTKFLT
        [SIGSTKFLT] = "STKFLT",  /* Linux on SPARC doesn't know SIGSTKFLT */
#endif
        [SIGCHLD]   = "CHLD",
        [SIGCONT]   = "CONT",
        [SIGSTOP]   = "STOP",
        [SIGTSTP]   = "TSTP",
        [SIGTTIN]   = "TTIN",
        [SIGTTOU]   = "TTOU",
        [SIGURG]    = "URG",
        [SIGXCPU]   = "XCPU",
        [SIGXFSZ]   = "XFSZ",
        [SIGVTALRM] = "VTALRM",
        [SIGPROF]   = "PROF",
        [SIGWINCH]  = "WINCH",
        [SIGIO]     = "IO",
        [SIGPWR]    = "PWR",
        [SIGSYS]    = "SYS"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(static_signal, int);

const char *signal_to_string(int signo) {
        static thread_local char buf[STRLEN("RTMIN+") + DECIMAL_STR_MAX(int)];
        const char *name;

        name = static_signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                xsprintf(buf, "RTMIN+%d", signo - SIGRTMIN);
        else
                xsprintf(buf, "%d", signo);

        return buf;
}

int signal_from_string(const char *s) {
        const char *p;
        int signo, r;

        /* Check that the input is a signal number. */
        if (safe_atoi(s, &signo) >= 0) {
                if (SIGNAL_VALID(signo))
                        return signo;
                else
                        return -ERANGE;
        }

        /* Drop "SIG" prefix. */
        if (startswith(s, "SIG"))
                s += 3;

        /* Check that the input is a signal name. */
        signo = static_signal_from_string(s);
        if (signo > 0)
                return signo;

        /* Check that the input is RTMIN or
         * RTMIN+n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMIN");
        if (p) {
                if (*p == '\0')
                        return SIGRTMIN;
                if (*p != '+')
                        return -EINVAL;

                r = safe_atoi(p, &signo);
                if (r < 0)
                        return r;

                if (signo < 0 || signo > SIGRTMAX - SIGRTMIN)
                        return -ERANGE;

                return signo + SIGRTMIN;
        }

        /* Check that the input is RTMAX or
         * RTMAX-n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMAX");
        if (p) {
                if (*p == '\0')
                        return SIGRTMAX;
                if (*p != '-')
                        return -EINVAL;

                r = safe_atoi(p, &signo);
                if (r < 0)
                        return r;

                if (signo > 0 || signo < SIGRTMIN - SIGRTMAX)
                        return -ERANGE;

                return signo + SIGRTMAX;
        }

        return -EINVAL;
}

void nop_signal_handler(int sig) {
        /* nothing here */
}

int signal_is_blocked(int sig) {
        sigset_t ss;
        int r;

        r = pthread_sigmask(SIG_SETMASK, NULL, &ss);
        if (r != 0)
                return -r;

        return RET_NERRNO(sigismember(&ss, sig));
}

int pop_pending_signal_internal(int sig, ...) {
        sigset_t ss;
        va_list ap;
        int r;

        if (sig < 0) /* Empty list? */
                return -EINVAL;

        if (sigemptyset(&ss) < 0)
                return -errno;

        /* Add first signal (if the signal is zero, we'll silently skip it, to make it easier to build
         * parameter lists where some element are sometimes off, similar to how sigset_add_many_ap() handles
         * this.) */
        if (sig > 0 && sigaddset(&ss, sig) < 0)
                return -errno;

        /* Add all other signals */
        va_start(ap, sig);
        r = sigset_add_many_ap(&ss, ap);
        va_end(ap);
        if (r < 0)
                return r;

        r = sigtimedwait(&ss, NULL, &(struct timespec) { 0, 0 });
        if (r < 0) {
                if (errno == EAGAIN)
                        return 0;

                return -errno;
        }

        return r; /* Returns the signal popped */
}

void propagate_signal(int sig, siginfo_t *siginfo) {
        pid_t p;

        /* To be called from a signal handler. Will raise the same signal again, in our process + in our threads.
         *
         * Note that we use raw_getpid() instead of getpid_cached(). We might have forked with raw_clone()
         * earlier (see PID 1), and hence let's go to the raw syscall here. In particular as this is not
         * performance sensitive code.
         *
         * Note that we use kill() rather than raise() as fallback, for similar reasons. */

        p = raw_getpid();

        if (rt_tgsigqueueinfo(p, gettid(), sig, siginfo) < 0)
                assert_se(kill(p, sig) >= 0);
}
