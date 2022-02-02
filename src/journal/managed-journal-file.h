/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"

typedef struct {
        JournalFile *file;
} ManagedJournalFile;

int managed_journal_file_open(
                int fd,
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                ManagedJournalFile *template,
                ManagedJournalFile **ret);

int managed_journal_file_set_offline(ManagedJournalFile *f, bool wait);
bool managed_journal_file_is_offlining(ManagedJournalFile *f);
ManagedJournalFile* managed_journal_file_close(ManagedJournalFile *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(ManagedJournalFile*, managed_journal_file_close);

int managed_journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                ManagedJournalFile *template,
                ManagedJournalFile **ret);

ManagedJournalFile* managed_journal_file_initiate_close(ManagedJournalFile *f, Set *deferred_closes);
int managed_journal_file_rotate(ManagedJournalFile **f, MMapCache *mmap_cache, bool compress, uint64_t compress_threshold_bytes, bool seal, Set *deferred_closes);
