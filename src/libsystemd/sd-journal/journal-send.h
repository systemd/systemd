/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int journal_fd_nonblock(bool nonblock);
void close_journal_fd(void);
