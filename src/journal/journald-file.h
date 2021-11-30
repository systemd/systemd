/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"

typedef struct {
        JournalFile *file;
} JournaldFile;

int journald_file_open(
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
                JournaldFile *template,
                JournaldFile **ret);

JournaldFile* journald_file_close(JournaldFile *f);
DEFINE_TRIVIAL_CLEANUP_FUNC(JournaldFile*, journald_file_close);

int journald_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                uint64_t compress_threshold_bytes,
                bool seal,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                Set *deferred_closes,
                JournaldFile *template,
                JournaldFile **ret);

JournaldFile* journald_file_initiate_close(JournaldFile *f, Set *deferred_closes);
int journald_file_rotate(JournaldFile **f, bool compress, uint64_t compress_threshold_bytes, bool seal, Set *deferred_closes);
