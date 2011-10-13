/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foojournalfilehfoo
#define foojournalfilehfoo

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>

#include "journal-def.h"
#include "util.h"
#include "sd-id128.h"

typedef struct JournalFile {
        int fd;
        char *path;
        struct stat last_stat;
        mode_t mode;
        int flags;
        int prot;
        bool writable;

        Header *header;

        HashItem *hash_table;
        void *hash_table_window;
        uint64_t hash_table_window_size;

        uint64_t *bisect_table;
        void *bisect_table_window;
        uint64_t bisect_table_window_size;

        void *window;
        uint64_t window_offset;
        uint64_t window_size;

        uint64_t current_offset;
} JournalFile;

typedef struct JournalCursor {
        uint8_t version;
        uint8_t reserved[7];
        uint64_t seqnum;
        sd_id128_t seqnum_id;
        sd_id128_t boot_id;
        uint64_t monotonic;
        uint64_t realtime;
        uint64_t xor_hash;
} JournalCursor;

int journal_file_open(const char *fname, int flags, mode_t mode, JournalFile *template, JournalFile **ret);

void journal_file_close(JournalFile *j);

int journal_file_move_to_object(JournalFile *f, uint64_t offset, int type, Object **ret);

uint64_t journal_file_entry_n_items(Object *o);

int journal_file_append_entry(JournalFile *f, const dual_timestamp *ts, const struct iovec iovec[], unsigned n_iovec, Object **ret, uint64_t *offset);

int journal_file_move_to_entry(JournalFile *f, uint64_t seqnum, Object **ret, uint64_t *offset);

int journal_file_find_first_entry(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset);
int journal_file_find_last_entry(JournalFile *f, const void *data, uint64_t size, Object **ret, uint64_t *offset);

int journal_file_next_entry(JournalFile *f, Object *o, Object **ret, uint64_t *offset);
int journal_file_prev_entry(JournalFile *f, Object *o, Object **ret, uint64_t *offset);

void journal_file_dump(JournalFile *f);

int journal_file_rotate(JournalFile **f);

int journal_directory_vacuum(const char *directory, uint64_t max_use, uint64_t min_free);


#endif
