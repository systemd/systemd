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

#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>

#include <systemd/sd-id128.h>

#include "journal-def.h"
#include "list.h"
#include "hashmap.h"
#include "set.h"
#include "journal-file.h"

typedef struct Match Match;
typedef struct Location Location;
typedef struct Directory Directory;

typedef enum MatchType {
        MATCH_DISCRETE,
        MATCH_OR_TERM,
        MATCH_AND_TERM
} MatchType;

struct Match {
        MatchType type;
        Match *parent;
        LIST_FIELDS(Match, matches);

        /* For concrete matches */
        char *data;
        size_t size;
        le64_t le_hash;

        /* For terms */
        LIST_HEAD(Match, matches);
};

typedef enum LocationType {
        /* The first and last entries, resp. */
        LOCATION_HEAD,
        LOCATION_TAIL,

        /* We already read the entry we currently point to, and the
         * next one to read should probably not be this one again. */
        LOCATION_DISCRETE,

        /* We should seek to the precise location specified, and
         * return it, as we haven't read it yet. */
        LOCATION_SEEK
} LocationType;

struct Location {
        LocationType type;

        bool seqnum_set;
        bool realtime_set;
        bool monotonic_set;
        bool xor_hash_set;

        uint64_t seqnum;
        sd_id128_t seqnum_id;

        uint64_t realtime;

        uint64_t monotonic;
        sd_id128_t boot_id;

        uint64_t xor_hash;
};

struct Directory {
        char *path;
        int wd;
        bool is_root;
};

struct sd_journal {
        char *path;
        char *prefix;

        Hashmap *files;
        MMapCache *mmap;

        Location current_location;

        JournalFile *current_file;
        uint64_t current_field;

        Match *level0, *level1, *level2;

        pid_t original_pid;

        int inotify_fd;
        unsigned current_invalidate_counter, last_invalidate_counter;
        usec_t last_process_usec;

        char *unique_field;
        JournalFile *unique_file;
        uint64_t unique_offset;

        int flags;

        bool on_network;
        bool no_new_files;

        size_t data_threshold;

        Hashmap *directories_by_path;
        Hashmap *directories_by_wd;

        Set *errors;
};

char *journal_make_match_string(sd_journal *j);
void journal_print_header(sd_journal *j);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_journal*, sd_journal_close);
#define _cleanup_journal_close_ _cleanup_(sd_journal_closep)

#define JOURNAL_FOREACH_DATA_RETVAL(j, data, l, retval)                     \
        for (sd_journal_restart_data(j); ((retval) = sd_journal_enumerate_data((j), &(data), &(l))) > 0; )
