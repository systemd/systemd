/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sysupdate-forward.h"

enum {
        PATTERN_MATCH_NO,
        PATTERN_MATCH_YES,
        PATTERN_MATCH_RETRY,
};

int pattern_match(const char *pattern, const char *s, InstanceMetadata *ret);
int pattern_match_many(char **patterns, const char *s, InstanceMetadata *ret);
int pattern_valid(const char *pattern);
int pattern_format(const char *pattern, const InstanceMetadata *fields, char **ret);
