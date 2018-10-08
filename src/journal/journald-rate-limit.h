/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "util.h"

typedef struct JournalRateLimit JournalRateLimit;

JournalRateLimit *journal_rate_limit_new(void);
void journal_rate_limit_free(JournalRateLimit *r);
int journal_rate_limit_test(JournalRateLimit *r, const char *id, usec_t rl_interval, unsigned rl_burst, int priority, uint64_t available);
