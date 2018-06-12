/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2011 Lennart Poettering
***/

#include "util.h"

typedef struct JournalRateLimit JournalRateLimit;

JournalRateLimit *journal_rate_limit_new(usec_t interval, unsigned burst);
void journal_rate_limit_free(JournalRateLimit *r);
int journal_rate_limit_test(JournalRateLimit *r, const char *id, int priority, uint64_t available);
