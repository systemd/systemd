/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <stdbool.h>

#include "journal-file.h"

int journal_file_append_tag(JournalFile *f);
int journal_file_maybe_append_tag(JournalFile *f, uint64_t realtime);
int journal_file_append_first_tag(JournalFile *f);

int journal_file_hmac_setup(JournalFile *f);
int journal_file_hmac_start(JournalFile *f);
int journal_file_hmac_put_header(JournalFile *f);
int journal_file_hmac_put_object(JournalFile *f, ObjectType type, Object *o, uint64_t p);

int journal_file_fss_load(JournalFile *f);
int journal_file_parse_verification_key(JournalFile *f, const char *key);

int journal_file_fsprg_evolve(JournalFile *f, uint64_t realtime);
int journal_file_fsprg_seek(JournalFile *f, uint64_t epoch);

bool journal_file_next_evolve_usec(JournalFile *f, usec_t *u);
