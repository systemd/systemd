/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
