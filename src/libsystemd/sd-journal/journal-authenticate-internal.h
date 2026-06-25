/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-def.h"
#include "sd-forward.h"

void journal_file_auth_done(JournalFile *f);
int journal_file_auth_load(JournalFile *f);
int journal_file_auth_load_key(JournalFile *f, const char *key);
int journal_file_auth_epoch_to_realtime_usec(JournalFile *f, uint64_t epoch, usec_t *ret_start, usec_t *ret_end);
int journal_file_auth_next_evolve_usec(JournalFile *f, usec_t *ret);
int journal_file_auth_seek(JournalFile *f, uint64_t goal);
int journal_file_auth_start(JournalFile *f);
int journal_file_auth_end(JournalFile *f, uint8_t ret[static TAG_LENGTH]);
int journal_file_auth_put_header(JournalFile *f);
int journal_file_auth_put_object(JournalFile *f, ObjectType type, Object *o, uint64_t p);
int journal_file_auth_append_tag(JournalFile *f);
int journal_file_auth_append_tag_first(JournalFile *f);
int journal_file_auth_append_tag_maybe(JournalFile *f, usec_t realtime);
