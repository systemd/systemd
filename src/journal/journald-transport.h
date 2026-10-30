/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

/* The transports we receive log messages on, whose string names match the _TRANSPORT= field. This is
 * used as index into JournalCounters.n_transport[], hence only ever append new entries, and bump
 * JOURNAL_COUNTERS_VERSION when doing so. */
typedef enum JournalTransport {
        JOURNAL_TRANSPORT_SYSLOG,
        JOURNAL_TRANSPORT_NATIVE,
        JOURNAL_TRANSPORT_STREAM,
        JOURNAL_TRANSPORT_AUDIT,
        JOURNAL_TRANSPORT_KERNEL,
        _JOURNAL_TRANSPORT_MAX,
        _JOURNAL_TRANSPORT_INVALID = -EINVAL,
} JournalTransport;

DECLARE_STRING_TABLE_LOOKUP(journal_transport, JournalTransport);
