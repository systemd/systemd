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

#include "sd-id128.h"

/* TODO:
 *
 *   - implement rotation
 *   - check LE/BE conversion for 8bit, 16bit, 32bit values
 *   - implement parallel traversal
 *   - implement audit gateway
 *   - implement native gateway
 *   - extend hash table/bisect table as we go
 */

typedef struct sd_journal sd_journal;

int sd_journal_open(sd_journal **ret);
void sd_journal_close(sd_journal *j);

int sd_journal_previous(sd_journal *j);
int sd_journal_next(sd_journal *j);

void* sd_journal_get(sd_journal *j, const char *field, size_t *size);
uint64_t sd_journal_get_seqnum(sd_journal *j);
uint64_t sd_journal_get_realtime_usec(sd_journal *j);
uint64_t sd_journal_get_monotonic_usec(sd_journal *j);

int sd_journal_add_match(sd_journal *j, const char *item, size_t *size);

int sd_journal_seek_head(sd_journal *j);
int sd_journal_seek_tail(sd_journal *j);

int sd_journal_seek_seqnum(sd_journal *j, uint64_t seqnum);
int sd_journal_seek_monotonic_usec(sd_journal *j, uint64_t usec);
int sd_journal_seek_realtime_usec(sd_journal *j, uint64_t usec);

uint64_t sd_journal_get_max_size(sd_journal *j);
uint64_t sd_journal_get_min_size(sd_journal *j);
uint64_t sd_journal_get_keep_free(sd_journal *j);

int sd_journal_set_max_size(sd_journal *j, uint64_t size);
int sd_journal_set_min_size(sd_journal *j, uint64_t size);
int sd_journal_set_keep_free(sd_journal *j, uint64_t size);

sd_id128_t sd_journal_get_file_id(sd_journal *j);
sd_id128_t sd_journal_get_machine_id(sd_journal *j);
sd_id128_t sd_journal_get_boot_id(sd_journal *j);

#endif
