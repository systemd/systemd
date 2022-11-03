/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int journal_fd_nonblock(bool nonblock);

#if VALGRIND
void close_journal_fd(void);
#else
static inline void close_journal_fd(void) {}
#endif
