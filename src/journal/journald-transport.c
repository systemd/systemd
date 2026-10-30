/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-transport.h"
#include "string-table.h"

static const char* const journal_transport_table[_JOURNAL_TRANSPORT_MAX] = {
        [JOURNAL_TRANSPORT_SYSLOG] = "syslog",
        [JOURNAL_TRANSPORT_NATIVE] = "journal",
        [JOURNAL_TRANSPORT_STREAM] = "stdout",
        [JOURNAL_TRANSPORT_AUDIT]  = "audit",
        [JOURNAL_TRANSPORT_KERNEL] = "kernel",
};

DEFINE_STRING_TABLE_LOOKUP(journal_transport, JournalTransport);
