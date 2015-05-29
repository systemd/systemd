/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "util.h"
#include "signal-util.h"

int reset_all_signal_handlers(void) {
        int sig, r = 0;

        for (sig = 1; sig < _NSIG; sig++) {
                static const struct sigaction sa = {
                        .sa_handler = SIG_DFL,
                        .sa_flags = SA_RESTART,
                };

                /* These two cannot be caught... */
                if (sig == SIGKILL || sig == SIGSTOP)
                        continue;

                /* On Linux the first two RT signals are reserved by
                 * glibc, and sigaction() will return EINVAL for them. */
                if ((sigaction(sig, &sa, NULL) < 0))
                        if (errno != EINVAL && r == 0)
                                r = -errno;
        }

        return r;
}

int reset_signal_mask(void) {
        sigset_t ss;

        if (sigemptyset(&ss) < 0)
                return -errno;

        if (sigprocmask(SIG_SETMASK, &ss, NULL) < 0)
                return -errno;

        return 0;
}

int sigaction_many(const struct sigaction *sa, ...) {
        va_list ap;
        int r = 0, sig;

        va_start(ap, sa);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

int ignore_signals(int sig, ...) {
        static const struct sigaction sa = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };
        va_list ap;
        int r = 0;

        if (sigaction(sig, &sa, NULL) < 0)
                r = -errno;

        va_start(ap, sig);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, &sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

int default_signals(int sig, ...) {
        static const struct sigaction sa = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_RESTART,
        };
        va_list ap;
        int r = 0;

        if (sigaction(sig, &sa, NULL) < 0)
                r = -errno;

        va_start(ap, sig);
        while ((sig = va_arg(ap, int)) > 0)
                if (sigaction(sig, &sa, NULL) < 0)
                        r = -errno;
        va_end(ap);

        return r;
}

void sigset_add_many(sigset_t *ss, ...) {
        va_list ap;
        int sig;

        assert(ss);

        va_start(ap, ss);
        while ((sig = va_arg(ap, int)) > 0)
                assert_se(sigaddset(ss, sig) == 0);
        va_end(ap);
}

int sigprocmask_many(int how, ...) {
        va_list ap;
        sigset_t ss;
        int sig;

        assert_se(sigemptyset(&ss) == 0);

        va_start(ap, how);
        while ((sig = va_arg(ap, int)) > 0)
                assert_se(sigaddset(&ss, sig) == 0);
        va_end(ap);

        if (sigprocmask(how, &ss, NULL) < 0)
                return -errno;

        return 0;
}

static const char *const __signal_table[] = {
        [SIGHUP] = "HUP",
        [SIGINT] = "INT",
        [SIGQUIT] = "QUIT",
        [SIGILL] = "ILL",
        [SIGTRAP] = "TRAP",
        [SIGABRT] = "ABRT",
        [SIGBUS] = "BUS",
        [SIGFPE] = "FPE",
        [SIGKILL] = "KILL",
        [SIGUSR1] = "USR1",
        [SIGSEGV] = "SEGV",
        [SIGUSR2] = "USR2",
        [SIGPIPE] = "PIPE",
        [SIGALRM] = "ALRM",
        [SIGTERM] = "TERM",
#ifdef SIGSTKFLT
        [SIGSTKFLT] = "STKFLT",  /* Linux on SPARC doesn't know SIGSTKFLT */
#endif
        [SIGCHLD] = "CHLD",
        [SIGCONT] = "CONT",
        [SIGSTOP] = "STOP",
        [SIGTSTP] = "TSTP",
        [SIGTTIN] = "TTIN",
        [SIGTTOU] = "TTOU",
        [SIGURG] = "URG",
        [SIGXCPU] = "XCPU",
        [SIGXFSZ] = "XFSZ",
        [SIGVTALRM] = "VTALRM",
        [SIGPROF] = "PROF",
        [SIGWINCH] = "WINCH",
        [SIGIO] = "IO",
        [SIGPWR] = "PWR",
        [SIGSYS] = "SYS"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(__signal, int);

const char *signal_to_string(int signo) {
        static thread_local char buf[sizeof("RTMIN+")-1 + DECIMAL_STR_MAX(int) + 1];
        const char *name;

        name = __signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                snprintf(buf, sizeof(buf), "RTMIN+%d", signo - SIGRTMIN);
        else
                snprintf(buf, sizeof(buf), "%d", signo);

        return buf;
}

int signal_from_string(const char *s) {
        int signo;
        int offset = 0;
        unsigned u;

        signo = __signal_from_string(s);
        if (signo > 0)
                return signo;

        if (startswith(s, "RTMIN+")) {
                s += 6;
                offset = SIGRTMIN;
        }
        if (safe_atou(s, &u) >= 0) {
                signo = (int) u + offset;
                if (signo > 0 && signo < _NSIG)
                        return signo;
        }
        return -EINVAL;
}

int signal_from_string_try_harder(const char *s) {
        int signo;
        assert(s);

        signo = signal_from_string(s);
        if (signo <= 0)
                if (startswith(s, "SIG"))
                        return signal_from_string(s+3);

        return signo;
}
