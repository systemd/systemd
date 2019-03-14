/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "journal-file.h"
#include "journal-importer.h"

typedef struct RemoteServer RemoteServer;

typedef struct Writer {
        JournalFile *journal;
        JournalMetrics metrics;

        MMapCache *mmap;
        RemoteServer *server;
        char *hashmap_key;

        uint64_t seqnum;

        unsigned n_ref;
} Writer;

Writer* writer_new(RemoteServer* server);
Writer* writer_ref(Writer *w);
Writer* writer_unref(Writer *w);

DEFINE_TRIVIAL_CLEANUP_FUNC(Writer*, writer_unref);

int writer_write(Writer *s,
                 struct iovec_wrapper *iovw,
                 dual_timestamp *ts,
                 sd_id128_t *boot_id,
                 bool compress,
                 bool seal);

typedef enum JournalWriteSplitMode {
        JOURNAL_WRITE_SPLIT_NONE,
        JOURNAL_WRITE_SPLIT_HOST,
        _JOURNAL_WRITE_SPLIT_MAX,
        _JOURNAL_WRITE_SPLIT_INVALID = -1
} JournalWriteSplitMode;
