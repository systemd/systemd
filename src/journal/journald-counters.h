/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <syslog.h>

#include "journald-forward.h"
#include "journald-transport.h"

#define JOURNAL_COUNTERS_VERSION UINT64_C(1)

/* This structure is kept in $RUNTIME_DIRECTORY/counters and is mapped by journald for its whole runtime.
 * It contains monotonic counters of received log messages, which hence survive journald restarts, but not
 * reboots. Native endian, not a stable interface. */
typedef struct JournalCounters {
        uint64_t version;
        uint64_t n_priority[LOG_DEBUG + 1];            /* indexed by LOG_PRI() */
        uint64_t n_transport[_JOURNAL_TRANSPORT_MAX];  /* indexed by JournalTransport */
} JournalCounters;

int manager_map_counters(Manager *m);

void manager_count_message(Manager *m, JournalTransport t, int priority);
