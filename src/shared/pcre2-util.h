/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_PCRE2

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

extern pcre2_match_data* (*sym_pcre2_match_data_create)(uint32_t, pcre2_general_context *);
extern void (*sym_pcre2_match_data_free)(pcre2_match_data *);
extern void (*sym_pcre2_code_free)(pcre2_code *);
extern pcre2_code* (*sym_pcre2_compile)(PCRE2_SPTR, PCRE2_SIZE, uint32_t, int *, PCRE2_SIZE *, pcre2_compile_context *);
extern int (*sym_pcre2_get_error_message)(int, PCRE2_UCHAR *, PCRE2_SIZE);
extern int (*sym_pcre2_match)(const pcre2_code *, PCRE2_SPTR, PCRE2_SIZE, PCRE2_SIZE, uint32_t, pcre2_match_data *, pcre2_match_context *);
extern PCRE2_SIZE* (*sym_pcre2_get_ovector_pointer)(pcre2_match_data *);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pcre2_match_data*, sym_pcre2_match_data_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(pcre2_code*, sym_pcre2_code_free, NULL);
#else

typedef struct {} pcre2_code;

#endif

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
