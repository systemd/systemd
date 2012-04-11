/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foojournalinternalhfoo
#define foojournalinternalhfoo

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

#include "list.h"

typedef struct Match Match;

struct Match {
        char *data;
        size_t size;
        le64_t le_hash;

        LIST_FIELDS(Match, matches);
};

typedef enum location_type {
        LOCATION_HEAD,
        LOCATION_TAIL,
        LOCATION_DISCRETE
} location_type_t;

typedef struct Location {
        location_type_t type;

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
} Location;

struct sd_journal {
        int flags;

        Hashmap *files;

        Location current_location;
        JournalFile *current_file;
        uint64_t current_field;

        int inotify_fd;
        Hashmap *inotify_wd_dirs;
        Hashmap *inotify_wd_roots;

        LIST_HEAD(Match, matches);
        unsigned n_matches;
};

#endif
