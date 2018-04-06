/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek
***/

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

        int n_ref;
} Writer;

Writer* writer_new(RemoteServer* server);
Writer* writer_free(Writer *w);

Writer* writer_ref(Writer *w);
Writer* writer_unref(Writer *w);

DEFINE_TRIVIAL_CLEANUP_FUNC(Writer*, writer_unref);
#define _cleanup_writer_unref_ _cleanup_(writer_unrefp)

int writer_write(Writer *s,
                 struct iovec_wrapper *iovw,
                 dual_timestamp *ts,
                 bool compress,
                 bool seal);

typedef enum JournalWriteSplitMode {
        JOURNAL_WRITE_SPLIT_NONE,
        JOURNAL_WRITE_SPLIT_HOST,
        _JOURNAL_WRITE_SPLIT_MAX,
        _JOURNAL_WRITE_SPLIT_INVALID = -1
} JournalWriteSplitMode;
