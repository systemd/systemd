/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-authenticate-internal.h"       /* IWYU pragma: export */
#include "journal-def.h"
#include "sd-forward.h"

#if HAVE_GCRYPT

JournalAuthContext* journal_auth_free(JournalAuthContext *c);
int journal_auth_load(JournalAuthContext **ret);
int journal_auth_load_key(JournalAuthContext **ret, const char *key);
int journal_auth_epoch_to_realtime_usec(const JournalAuthContext *c, uint64_t epoch, usec_t *ret_start, usec_t *ret_end);
int journal_auth_next_evolve_usec(const JournalAuthContext *c, usec_t *ret);
int journal_auth_seek(JournalAuthContext *c, uint64_t goal);
int journal_auth_start(JournalAuthContext *c);
int journal_auth_end(JournalAuthContext *c, uint8_t ret[static TAG_LENGTH]);
int journal_auth_put_header(JournalAuthContext *c, JournalFile *f);
int journal_auth_put_object(JournalAuthContext *c, JournalFile *f, ObjectType type, Object *o, uint64_t p);
int journal_auth_append_tag(JournalAuthContext *c, JournalFile *f);
int journal_auth_append_tag_first(JournalAuthContext *c, JournalFile *f);
int journal_auth_append_tag_maybe(JournalAuthContext *c, JournalFile *f, usec_t realtime);

#endif
