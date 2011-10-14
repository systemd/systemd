/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foojournalhfoo
#define foojournalhfoo

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
#include <sys/types.h>

/* TODO:
 *
 *   - check LE/BE conversion for 8bit, 16bit, 32bit values
 *   - implement parallel traversal
 *   - implement inotify usage on client
 *   - implement audit gateway
 *   - implement native gateway
 *   - implement stdout gateway
 *   - extend hash table/bisect table as we go
 *   - accelerate looking for "all hostnames" and suchlike.
 *   - throttling
 *   - enforce limit on open journal files in journald and journalctl
 */

typedef struct sd_journal sd_journal;

int sd_journal_open(sd_journal **ret);
void sd_journal_close(sd_journal *j);

int sd_journal_previous(sd_journal *j);
int sd_journal_next(sd_journal *j);

int sd_journal_get_realtime_usec(sd_journal *j, uint64_t *ret);
int sd_journal_get_monotonic_usec(sd_journal *j, uint64_t *ret);
int sd_journal_get_field(sd_journal *j, const char *field, const void **data, size_t *l);
int sd_journal_iterate_fields(sd_journal *j, const void **data, size_t *l);

int sd_journal_add_match(sd_journal *j, const void *data, size_t size);
void sd_journal_flush_matches(sd_journal *j);

int sd_journal_seek_head(sd_journal *j);
int sd_journal_seek_tail(sd_journal *j);

int sd_journal_seek_monotonic_usec(sd_journal *j, uint64_t usec);
int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec);

int sd_journal_get_cursor(sd_journal *j, char **cursor);
int sd_journal_set_cursor(sd_journal *j, const char *cursor);

int sd_journal_get_fd(sd_journal *j);

enum {
        SD_JOURNAL_NOP,
        SD_JOURNAL_APPEND,
        SD_JOURNAL_DROP
};

int sd_journal_process(sd_journal *j);

#define SD_JOURNAL_FOREACH(j)                   \
        while (sd_journal_next(j) > 0)

#define SD_JOURNAL_FOREACH_BACKWARDS(j)         \
        while (sd_journal_previous(j) > 0)

#define SD_JOURNAL_FOREACH_FIELD(j, data, l)                            \
        while (sd_journal_iterate_fields((j), &(data), &(l)) > 0)

#endif
