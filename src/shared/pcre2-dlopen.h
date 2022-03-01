/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
#endif

int dlopen_pcre2(void);
