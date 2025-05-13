/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"

typedef struct RemoteServer RemoteServer;

typedef struct Writer {
        JournalFile *journal;
        JournalMetrics metrics;
        char *output;          /* directory where we write, for vacuuming */

        MMapCache *mmap;
        RemoteServer *server;
        char *hashmap_key;

        uint64_t seqnum;

        unsigned n_ref;
} Writer;

int writer_new(RemoteServer *server, Writer **ret);
Writer* writer_ref(Writer *w);
Writer* writer_unref(Writer *w);

DEFINE_TRIVIAL_CLEANUP_FUNC(Writer*, writer_unref);

int writer_write(Writer *s,
                 const struct iovec_wrapper *iovw,
                 const dual_timestamp *ts,
                 const sd_id128_t *boot_id,
                 JournalFileFlags file_flags);

typedef enum JournalWriteSplitMode {
        JOURNAL_WRITE_SPLIT_NONE,
        JOURNAL_WRITE_SPLIT_HOST,
        _JOURNAL_WRITE_SPLIT_MAX,
        _JOURNAL_WRITE_SPLIT_INVALID = -EINVAL,
} JournalWriteSplitMode;
