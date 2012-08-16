/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <inttypes.h>

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif

#include <systemd/sd-id128.h>

#include "sparse-endian.h"
#include "journal-def.h"
#include "util.h"
#include "mmap-cache.h"

typedef struct JournalMetrics {
        uint64_t max_use;
        uint64_t max_size;
        uint64_t min_size;
        uint64_t keep_free;
} JournalMetrics;

typedef struct JournalFile {
        int fd;
        char *path;
        struct stat last_stat;
        mode_t mode;

        int flags;
        int prot;
        bool writable;
        bool compress;
        bool authenticate;

        bool tail_entry_monotonic_valid;

        Header *header;
        HashItem *data_hash_table;
        HashItem *field_hash_table;

        uint64_t current_offset;

        JournalMetrics metrics;
        MMapCache *mmap;

#ifdef HAVE_XZ
        void *compress_buffer;
        uint64_t compress_buffer_size;
#endif

#ifdef HAVE_GCRYPT
        gcry_md_hd_t hmac;
        bool hmac_running;

        FSPRGHeader *fsprg_header;
        size_t fsprg_size;
#endif
} JournalFile;

typedef enum direction {
        DIRECTION_UP,
        DIRECTION_DOWN
} direction_t;

int journal_file_open(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                bool authenticate,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile *template,
                JournalFile **ret);

void journal_file_close(JournalFile *j);

int journal_file_open_reliably(
                const char *fname,
                int flags,
                mode_t mode,
                bool compress,
                bool authenticate,
                JournalMetrics *metrics,
                MMapCache *mmap_cache,
                JournalFile *template,
                JournalFile **ret);

#define ALIGN64(x) (((x) + 7ULL) & ~7ULL)

#define JOURNAL_HEADER_CONTAINS(h, field) \
        (le64toh((h)->header_size) >= offsetof(Header, field) + sizeof((h)->field))

int journal_file_move_to_object(JournalFile *f, int type, uint64_t offset, Object **ret);

uint64_t journal_file_entry_n_items(Object *o);
uint64_t journal_file_entry_array_n_items(Object *o);

int journal_file_append_object(JournalFile *f, int type, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_append_entry(JournalFile *f, const dual_timestamp *ts, const struct iovec iovec[], unsigned n_iovec, uint64_t *seqno, Object **ret, uint64_t *offset);

int journal_file_find_data_object(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_find_data_object_with_hash(JournalFile *f, const void *data, uint64_t size, uint64_t hash, Object **ret, uint64_t *offset);

int journal_file_next_entry(JournalFile *f, Object *o, uint64_t p, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_skip_entry(JournalFile *f, Object *o, uint64_t p, int64_t skip, Object **ret, uint64_t *offset);

int journal_file_next_entry_for_data(JournalFile *f, Object *o, uint64_t p, uint64_t data_offset, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_move_to_entry_by_offset(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_seqnum(JournalFile *f, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_realtime(JournalFile *f, uint64_t realtime, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_monotonic(JournalFile *f, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_move_to_entry_by_offset_for_data(JournalFile *f, uint64_t data_offset, uint64_t p, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_seqnum_for_data(JournalFile *f, uint64_t data_offset, uint64_t seqnum, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_realtime_for_data(JournalFile *f, uint64_t data_offset, uint64_t realtime, direction_t direction, Object **ret, uint64_t *offset);
int journal_file_move_to_entry_by_monotonic_for_data(JournalFile *f, uint64_t data_offset, sd_id128_t boot_id, uint64_t monotonic, direction_t direction, Object **ret, uint64_t *offset);

int journal_file_copy_entry(JournalFile *from, JournalFile *to, Object *o, uint64_t p, uint64_t *seqnum, Object **ret, uint64_t *offset);

void journal_file_dump(JournalFile *f);
void journal_file_print_header(JournalFile *f);

int journal_file_rotate(JournalFile **f, bool compress, bool authenticate);

void journal_file_post_change(JournalFile *f);

void journal_default_metrics(JournalMetrics *m, int fd);

int journal_file_get_cutoff_realtime_usec(JournalFile *f, usec_t *from, usec_t *to);
int journal_file_get_cutoff_monotonic_usec(JournalFile *f, sd_id128_t boot, usec_t *from, usec_t *to);

bool journal_file_rotate_suggested(JournalFile *f);
