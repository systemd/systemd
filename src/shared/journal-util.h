/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-journal.h" /* IWYU pragma: export */

#include "forward.h"

int journal_access_blocked(sd_journal *j);
int journal_access_check_and_warn(sd_journal *j, bool quiet, bool want_other_users);
int journal_open_machine(sd_journal **ret, const char *machine, int flags);
