/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <signal.h>

#include "macro.h"

int reset_all_signal_handlers(void);
int reset_signal_mask(void);

int ignore_signals(int sig, ...);
int default_signals(int sig, ...);
int sigaction_many(const struct sigaction *sa, ...);

int sigset_add_many(sigset_t *ss, ...);
int sigprocmask_many(int how, sigset_t *old, ...);

const char *signal_to_string(int i) _const_;
int signal_from_string(const char *s) _pure_;

void nop_signal_handler(int sig);

static inline void block_signals_reset(sigset_t *ss) {
        assert_se(sigprocmask(SIG_SETMASK, ss, NULL) >= 0);
}

#define BLOCK_SIGNALS(...)                                                         \
        _cleanup_(block_signals_reset) _unused_ sigset_t _saved_sigset = ({        \
                sigset_t _t;                                                       \
                assert_se(sigprocmask_many(SIG_BLOCK, &_t, __VA_ARGS__, -1) >= 0); \
                _t;                                                                \
        })

static inline bool SIGNAL_VALID(int signo) {
        return signo > 0 && signo < _NSIG;
}

static inline const char* signal_to_string_with_check(int n) {
        if (!SIGNAL_VALID(n))
                return NULL;

        return signal_to_string(n);
}
