/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

typedef void pcre2_pattern;

typedef enum {
        PATTERN_COMPILE_CASE_AUTO,
        PATTERN_COMPILE_CASE_SENSITIVE,
        PATTERN_COMPILE_CASE_INSENSITIVE,
        _PATTERN_COMPILE_CASE_MAX,
        _PATTERN_COMPILE_CASE_INVALID = -EINVAL,
} PatternCompileCase;

int pcre2_pattern_compile(const char *pattern, PatternCompileCase case_, pcre2_pattern **ret);
int pcre2_pattern_matches(pcre2_pattern *compiled_pattern, const char *message, size_t size, size_t *ret_ovec);
void *pcre2_pattern_free(pcre2_pattern *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(pcre2_pattern*, pcre2_pattern_free);

int dlopen_pcre2(void);
