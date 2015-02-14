/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once


#include "journal-file.h"

typedef struct RemoteServer RemoteServer;

struct iovec_wrapper {
        struct iovec *iovec;
        size_t size_bytes;
        size_t count;
};

int iovw_put(struct iovec_wrapper *iovw, void* data, size_t len);
void iovw_free_contents(struct iovec_wrapper *iovw);
size_t iovw_size(struct iovec_wrapper *iovw);
void iovw_rebase(struct iovec_wrapper *iovw, char *old, char *new);

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
