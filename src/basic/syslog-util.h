/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int log_facility_unshifted_to_string_alloc(int i, char **s);
int log_facility_unshifted_from_string(const char *s);
bool log_facility_unshifted_is_valid(int faciliy);

int log_level_to_string_alloc(int i, char **s);
int log_level_from_string(const char *s);
bool log_level_is_valid(int level);

int syslog_parse_priority(const char **p, int *priority, bool with_facility);

bool log_namespace_name_valid(const char *s);
