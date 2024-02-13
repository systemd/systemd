/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "journal-file.h"
#include "macro.h"

void journal_file_finalize(JournalFile *f, uint8_t state);
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

int journal_file_archive(JournalFile *f);

int journal_file_rotate(
                JournalFile **f,
                MMapCache *mmap_cache,
                JournalFileFlags file_flags,
                uint64_t compress_threshold_bytes);
