/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h" /* IWYU pragma: export */
#include "forward.h"

int journal_file_set_offline(JournalFile *f, bool wait);
bool journal_file_is_offlining(JournalFile *f);
void journal_file_write_final_tag(JournalFile *f);
JournalFile* journal_file_offline_close(JournalFile *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(JournalFile*, journal_file_offline_close);

int journal_file_open_reliably(
                const char *fname,
                int open_flags,
                JournalFileFlags file_flags,
                mode_t mode,
                uint64_t compress_threshold_bytes,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile **ret);

JournalFile* journal_file_initiate_close(JournalFile *f, Set *deferred_closes);
int journal_file_rotate(
                JournalFile **f,
                MMapCache *mmap_cache,
                JournalFileFlags file_flags,
                uint64_t compress_threshold_bytes,
                Set *deferred_closes);

extern const struct hash_ops journal_file_hash_ops_offline_close;
