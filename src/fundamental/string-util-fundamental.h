/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef SD_BOOT
#include <efi.h>
#include <efilib.h>
#else
#include <string.h>
#endif

#include "macro-fundamental.h"

#ifdef SD_BOOT
#define strlen(a)        StrLen((a))
#define strcmp(a, b)     StrCmp((a), (b))
#define strncmp(a, b, n) StrnCmp((a), (b), (n))
#define strcasecmp(a, b) StriCmp((a), (b))
#define STR_C(str)       (L ## str)
#else
#define STR_C(str)       (str)
#endif

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#ifndef SD_BOOT
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)
#endif

static inline sd_int strcmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcmp(a, b);

        return CMP(a, b);
}

static inline sd_int strcasecmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcasecmp(a, b);

        return CMP(a, b);
}

static inline sd_bool streq_ptr(const sd_char *a, const sd_char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline sd_bool strcaseeq_ptr(const sd_char *a, const sd_char *b) {
        return strcasecmp_ptr(a, b) == 0;
}

sd_char *startswith(const sd_char *s, const sd_char *prefix) _pure_;
#ifndef SD_BOOT
sd_char *startswith_no_case(const sd_char *s, const sd_char *prefix) _pure_;
#endif
sd_char *endswith(const sd_char *s, const sd_char *postfix) _pure_;
sd_char *endswith_no_case(const sd_char *s, const sd_char *postfix) _pure_;

static inline sd_bool isempty(const sd_char *a) {
        return !a || a[0] == '\0';
}

static inline const sd_char *yes_no(sd_bool b) {
        return b ? STR_C("yes") : STR_C("no");
}

sd_int strverscmp_improved(const sd_char *a, const sd_char *b);
