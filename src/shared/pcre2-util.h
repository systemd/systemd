/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hash-funcs.h"
#include "macro.h"

#if HAVE_PCRE2

#include "dlfcn-util.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

extern DLSYM_PROTOTYPE(pcre2_match_data_create);
extern DLSYM_PROTOTYPE(pcre2_match_data_free);
extern DLSYM_PROTOTYPE(pcre2_code_free);
extern DLSYM_PROTOTYPE(pcre2_compile);
extern DLSYM_PROTOTYPE(pcre2_get_error_message);
extern DLSYM_PROTOTYPE(pcre2_match);
extern DLSYM_PROTOTYPE(pcre2_get_ovector_pointer);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pcre2_match_data*, sym_pcre2_match_data_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pcre2_code*, sym_pcre2_code_free, NULL);
#else

typedef struct {} pcre2_code;

#endif

extern const struct hash_ops pcre2_code_hash_ops_free;

typedef enum {
        PATTERN_COMPILE_CASE_AUTO,
        PATTERN_COMPILE_CASE_SENSITIVE,
        PATTERN_COMPILE_CASE_INSENSITIVE,
        _PATTERN_COMPILE_CASE_MAX,
        _PATTERN_COMPILE_CASE_INVALID = -EINVAL,
} PatternCompileCase;

int pattern_compile_and_log(const char *pattern, PatternCompileCase case_, pcre2_code **ret);
int pattern_matches_and_log(pcre2_code *compiled_pattern, const char *message, size_t size, size_t *ret_ovec);
void *pattern_free(pcre2_code *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(pcre2_code*, pattern_free);

int dlopen_pcre2(void);
