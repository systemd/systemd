/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

typedef struct JournalRateLimit JournalRateLimit;

JournalRateLimit *journal_ratelimit_new(void);
void journal_ratelimit_free(JournalRateLimit *r);
int journal_ratelimit_test(JournalRateLimit *r, const char *id, usec_t rl_interval, unsigned rl_burst, int priority, uint64_t available);
