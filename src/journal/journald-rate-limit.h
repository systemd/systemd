/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"
#include "time-util.h"

int journal_ratelimit_test(Server *s, const char *id, usec_t rl_interval, unsigned rl_burst, int priority, uint64_t available);
