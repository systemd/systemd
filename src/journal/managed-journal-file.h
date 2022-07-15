/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"

typedef struct {
        JournalFile *file;
} ManagedJournalFile;

int managed_journal_file_open(
                int fd,
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
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
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                ManagedJournalFile *template,
                ManagedJournalFile **ret);

ManagedJournalFile* managed_journal_file_initiate_close(ManagedJournalFile *f, Set *deferred_closes);
int managed_journal_file_rotate(ManagedJournalFile **f, MMapCache *mmap_cache, JournalFileFlags file_flags, uint64_t compress_threshold_bytes, Set *deferred_closes);
