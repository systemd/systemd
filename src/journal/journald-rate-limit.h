/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "hashmap.h"
#include "time-util.h"

int journal_ratelimit_test(
                OrderedHashmap **groups_by_id,
                const char *id,
                usec_t rl_interval,
                unsigned rl_burst,
                int priority,
                uint64_t available);
