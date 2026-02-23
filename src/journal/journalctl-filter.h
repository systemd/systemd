/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int journal_add_unit_matches(
                sd_journal *j,
                MatchUnitFlag flags,
                UnitNameMangle mangle_flags,
                char * const *system_units,
                uid_t uid,
                char * const *user_units);

int add_filters(sd_journal *j, char **matches);
