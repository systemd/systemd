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
        LOCATION_HEAD,
        LOCATION_TAIL,
        LOCATION_DISCRETE
} LocationType;

struct Location {
        LocationType type;

        uint64_t seqnum;
        sd_id128_t seqnum_id;
        bool seqnum_set;

        uint64_t realtime;
        bool realtime_set;

        uint64_t monotonic;
        sd_id128_t boot_id;
        bool monotonic_set;

        uint64_t xor_hash;
        bool xor_hash_set;
};

struct Directory {
        char *path;
        int wd;
        bool is_root;
};

struct sd_journal {
        int flags;

        char *path;

        Hashmap *files;

        Location current_location;

        JournalFile *current_file;
        uint64_t current_field;

        Hashmap *directories_by_path;
        Hashmap *directories_by_wd;

        int inotify_fd;

        Match *level0, *level1;

        unsigned current_invalidate_counter, last_invalidate_counter;
};

char *journal_make_match_string(sd_journal *j);
void journal_print_header(sd_journal *j);

