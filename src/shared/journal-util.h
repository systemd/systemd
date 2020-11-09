/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

#include "sd-journal.h"

bool journal_field_valid(const char *p, size_t l, bool allow_protected);
int journal_access_blocked(sd_journal *j);
int journal_access_check_and_warn(sd_journal *j, bool quiet, bool want_other_users);
