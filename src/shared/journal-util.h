/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "sd-journal.h"

#include "journal-internal.h"

int journal_access_blocked(sd_journal *j);
int journal_access_check_and_warn(sd_journal *j, bool quiet, bool want_other_users);

bool journal_shall_try_append_again(JournalFile *f, int r);

int journal_enumerate_objects(sd_journal *j, Object **object, uint64_t *offset);
void journal_restart_objects(sd_journal *j);

#define JOURNAL_FOREACH_OBJECT(j, object, offset) \
        for (journal_restart_objects(j); journal_enumerate_objects((j), &(object), &(offset)) > 0; )
