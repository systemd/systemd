/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>

#include "macro.h"

int reset_all_signal_handlers(void);
int reset_signal_mask(void);

int sigaction_many_internal(const struct sigaction *sa, ...);

#define ignore_signals(...)                                             \
        sigaction_many_internal(                                        \
                        &sigaction_ignore,                              \
                        __VA_ARGS__,                                    \
                        -1)

#define default_signals(...)                                            \
        sigaction_many_internal(                                        \
                        &sigaction_default,                             \
                        __VA_ARGS__,                                    \
                        -1)

#define sigaction_many(sa, ...)                                         \
        sigaction_many_internal(sa, __VA_ARGS__, -1)

int sigset_add_many_internal(sigset_t *ss, ...);
#define sigset_add_many(...) sigset_add_many_internal(__VA_ARGS__, -1)

int sigprocmask_many_internal(int how, sigset_t *ret_old_mask, ...);
#define sigprocmask_many(...) sigprocmask_many_internal(__VA_ARGS__, -1)

const char* signal_to_string(int i) _const_;
int signal_from_string(const char *s) _pure_;

void nop_signal_handler(int sig);

static inline void block_signals_reset(sigset_t *ss) {
        assert_se(sigprocmask(SIG_SETMASK, ss, NULL) >= 0);
}

#define BLOCK_SIGNALS(...)                                                         \
        _cleanup_(block_signals_reset) _unused_ sigset_t _saved_sigset = ({        \
                sigset_t _t;                                                       \
                assert_se(sigprocmask_many(SIG_BLOCK, &_t, __VA_ARGS__) >= 0);     \
                _t;                                                                \
        })
#define SIGNO_INVALID (-EINVAL)

static inline bool SIGNAL_VALID(int signo) {
        return signo > 0 && signo < _NSIG;
}

static inline const char* signal_to_string_with_check(int n) {
        if (!SIGNAL_VALID(n))
                return NULL;

        return signal_to_string(n);
}

int signal_is_blocked(int sig);

int pop_pending_signal_internal(int sig, ...);
#define pop_pending_signal(...) pop_pending_signal_internal(__VA_ARGS__, -1)

void propagate_signal(int sig, siginfo_t *siginfo);

extern const struct sigaction sigaction_ignore;
extern const struct sigaction sigaction_default;
extern const struct sigaction sigaction_nop_nocldstop;

int parse_signo(const char *s, int *ret);
