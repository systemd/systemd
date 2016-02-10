#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2015 Lennart Poettering

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

int signal_from_string_try_harder(const char *s);

void nop_signal_handler(int sig);

static inline void block_signals_reset(sigset_t *ss) {
        assert_se(sigprocmask(SIG_SETMASK, ss, NULL) >= 0);
}

#define BLOCK_SIGNALS(...)                                              \
        _cleanup_(block_signals_reset) sigset_t _saved_sigset = ({      \
                sigset_t t;                                             \
                assert_se(sigprocmask_many(SIG_BLOCK, &t, __VA_ARGS__, -1) >= 0); \
                t;                                                      \
        })
