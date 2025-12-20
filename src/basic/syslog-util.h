/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

DECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_facility_unshifted, int);
bool log_facility_unshifted_is_valid(int faciliy);

DECLARE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_level, int);
bool log_level_is_valid(int level);

int syslog_parse_priority(const char **p, int *priority, bool with_facility);

bool log_namespace_name_valid(const char *s);
