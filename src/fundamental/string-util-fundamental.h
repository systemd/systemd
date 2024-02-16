/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if SD_BOOT
#  include "efi.h"
#  include "efi-string.h"
#else
#  include <string.h>
#endif

#include "macro-fundamental.h"

#if SD_BOOT
#  define strlen strlen16
#  define strcmp strcmp16
#  define strncmp strncmp16
#  define strcasecmp strcasecmp16
#  define strncasecmp strncasecmp16
#  define STR_C(str)       (L ## str)
typedef char16_t sd_char;
#else
#  define STR_C(str)       (str)
typedef char sd_char;
#endif

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

static inline int strcmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcmp(a, b);

        return CMP(a, b);
}

static inline int strcasecmp_ptr(const sd_char *a, const sd_char *b) {
        if (a && b)
                return strcasecmp(a, b);

        return CMP(a, b);
}

static inline bool streq_ptr(const sd_char *a, const sd_char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline bool strcaseeq_ptr(const sd_char *a, const sd_char *b) {
        return strcasecmp_ptr(a, b) == 0;
}

static inline size_t strlen_ptr(const sd_char *s) {
        if (!s)
                return 0;

        return strlen(s);
}

sd_char *startswith(const sd_char *s, const sd_char *prefix) _pure_;
sd_char *startswith_no_case(const sd_char *s, const sd_char *prefix) _pure_;
sd_char *endswith(const sd_char *s, const sd_char *suffix) _pure_;
sd_char *endswith_no_case(const sd_char *s, const sd_char *suffix) _pure_;

static inline bool isempty(const sd_char *a) {
        return !a || a[0] == '\0';
}

static inline const sd_char *strempty(const sd_char *s) {
        return s ?: STR_C("");
}

static inline const sd_char *yes_no(bool b) {
        return b ? STR_C("yes") : STR_C("no");
}

static inline const sd_char *on_off(bool b) {
        return b ? STR_C("on") : STR_C("off");
}

static inline const sd_char* comparison_operator(int result) {
        return result < 0 ? STR_C("<") : result > 0 ? STR_C(">") : STR_C("==");
}

int strverscmp_improved(const sd_char *a, const sd_char *b);

/* Like startswith(), but operates on arbitrary memory blocks */
static inline void *memory_startswith(const void *p, size_t sz, const sd_char *token) {
        assert(token);

        size_t n = strlen(token) * sizeof(sd_char);
        if (sz < n)
                return NULL;

        assert(p);

        if (memcmp(p, token, n) != 0)
                return NULL;

        return (uint8_t*) p + n;
}

#define _STRV_FOREACH(s, l, i)                                          \
        for (typeof(*(l)) *s, *i = (l); (s = i) && *i; i++)

#define STRV_FOREACH(s, l)                      \
        _STRV_FOREACH(s, l, UNIQ_T(i, UNIQ))

static inline bool ascii_isdigit(sd_char a) {
        /* A pure ASCII, locale independent version of isdigit() */
        return a >= '0' && a <= '9';
}

static inline bool ascii_ishex(sd_char a) {
        return ascii_isdigit(a) || (a >= 'a' && a <= 'f') || (a >= 'A' && a <= 'F');
}

static inline bool ascii_isalpha(sd_char a) {
        /* A pure ASCII, locale independent version of isalpha() */
        return (a >= 'a' && a <= 'z') || (a >= 'A' && a <= 'Z');
}
