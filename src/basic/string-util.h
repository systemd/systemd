/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"
#include "string-util-fundamental.h"
#include "utf8.h"

/* What is interpreted as whitespace? */
#define WHITESPACE          " \t\n\r"
#define NEWLINE             "\n\r"
#define QUOTES              "\"\'"
#define COMMENTS            "#;"
#define GLOB_CHARS          "*?["
#define DIGITS              "0123456789"
#define LOWERCASE_LETTERS   "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS             LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL      LETTERS DIGITS
#define HEXDIGITS           DIGITS "abcdefABCDEF"
#define LOWERCASE_HEXDIGITS DIGITS "abcdef"
#define URI_RESERVED        ":/?#[]@!$&'()*+;="         /* [RFC3986] */
#define URI_UNRESERVED      ALPHANUMERICAL "-._~"       /* [RFC3986] */
#define URI_VALID           URI_RESERVED URI_UNRESERVED /* [RFC3986] */

static inline char* strstr_ptr(const char *haystack, const char *needle) {
        if (!haystack || !needle)
                return NULL;
        return strstr(haystack, needle);
}

static inline char* strstrafter(const char *haystack, const char *needle) {
        char *p;

        /* Returns NULL if not found, or pointer to first character after needle if found */

        p = strstr_ptr(haystack, needle);
        if (!p)
                return NULL;

        return p + strlen(needle);
}

static inline const char* strnull(const char *s) {
        return s ?: "(null)";
}

static inline const char* strna(const char *s) {
        return s ?: "n/a";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* plus_minus(bool b) {
        return b ? "+" : "-";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

static inline const char* enable_disable(bool b) {
        return b ? "enable" : "disable";
}

static inline const char* enabled_disabled(bool b) {
        return b ? "enabled" : "disabled";
}

/* This macro's return pointer will have the "const" qualifier set or unset the same way as the input
 * pointer. */
#define empty_to_null(p)                                \
        ({                                              \
                const char *_p = (p);                   \
                (typeof(p)) (isempty(_p) ? NULL : _p);  \
        })

static inline const char* empty_to_na(const char *p) {
        return isempty(p) ? "n/a" : p;
}

static inline const char* empty_to_dash(const char *str) {
        return isempty(str) ? "-" : str;
}

static inline bool empty_or_dash(const char *str) {
        return !str ||
                str[0] == 0 ||
                (str[0] == '-' && str[1] == 0);
}

static inline const char* empty_or_dash_to_null(const char *p) {
        return empty_or_dash(p) ? NULL : p;
}
#define empty_or_dash_to_null(p)                                \
        ({                                                      \
                const char *_p = (p);                           \
                (typeof(p)) (empty_or_dash(_p) ? NULL : _p);    \
        })

char* first_word(const char *s, const char *word) _pure_;

char* strnappend(const char *s, const char *suffix, size_t length);

#define strjoin(a, ...) strextend_with_separator_internal(NULL, NULL, a, __VA_ARGS__, NULL)

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                size_t _len_ = 0;                                       \
                size_t _i_;                                             \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = newa(char, _len_ + 1);                      \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

char* strstrip(char *s);
char* delete_chars(char *s, const char *bad);
char* delete_trailing_chars(char *s, const char *bad);
char* truncate_nl_full(char *s, size_t *ret_len);
static inline char* truncate_nl(char *s) {
        return truncate_nl_full(s, NULL);
}

static inline char* skip_leading_chars(const char *s, const char *bad) {
        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        return (char*) s + strspn(s, bad);
}

char ascii_tolower(char x);
char* ascii_strlower(char *s);
char* ascii_strlower_n(char *s, size_t n);

char ascii_toupper(char x);
char* ascii_strupper(char *s);

int ascii_strcasecmp_n(const char *a, const char *b, size_t n);
int ascii_strcasecmp_nn(const char *a, size_t n, const char *b, size_t m);

bool chars_intersect(const char *a, const char *b) _pure_;

static inline bool _pure_ in_charset(const char *s, const char *charset) {
        assert(s);
        assert(charset);
        return s[strspn(s, charset)] == '\0';
}

static inline bool char_is_cc(char p) {
        /* char is unsigned on some architectures, e.g. aarch64. So, compiler may warn the condition
         * p >= 0 is always true. See #19543. Hence, let's cast to unsigned before the comparison. Note
         * that the cast in the right hand side is redundant, as according to the C standard, compilers
         * automatically cast a signed value to unsigned when comparing with an unsigned variable. Just
         * for safety and readability. */
        return (uint8_t) p < (uint8_t) ' ' || p == 127;
}
bool string_has_cc(const char *p, const char *ok) _pure_;

char* ellipsize_mem(const char *s, size_t old_length_bytes, size_t new_length_columns, unsigned percent);
static inline char* ellipsize(const char *s, size_t length, unsigned percent) {
        return ellipsize_mem(s, strlen(s), length, percent);
}

char* cellescape(char *buf, size_t len, const char *s);

/* This limit is arbitrary, enough to give some idea what the string contains */
#define CELLESCAPE_DEFAULT_LENGTH 64

char* strshorten(char *s, size_t l);

int strgrowpad0(char **s, size_t l);

char* strreplace(const char *text, const char *old_string, const char *new_string);

char* strip_tab_ansi(char **ibuf, size_t *_isz, size_t highlight[2]);

char* strextend_with_separator_internal(char **x, const char *separator, ...) _sentinel_;
#define strextend_with_separator(x, separator, ...) strextend_with_separator_internal(x, separator, __VA_ARGS__, NULL)
#define strextend(x, ...) strextend_with_separator_internal(x, NULL, __VA_ARGS__, NULL)

char* strextendn(char **x, const char *s, size_t l);

int strextendf_with_separator(char **x, const char *separator, const char *format, ...) _printf_(3,4);
#define strextendf(x, ...) strextendf_with_separator(x, NULL, __VA_ARGS__)

char* strrep(const char *s, unsigned n);

#define strrepa(s, n)                                                   \
        ({                                                              \
                const char *_sss_ = (s);                                \
                size_t _nnn_ = (n), _len_ = strlen(_sss_);              \
                assert_se(MUL_ASSIGN_SAFE(&_len_, _nnn_));              \
                char *_d_, *_p_;                                        \
                _p_ = _d_ = newa(char, _len_ + 1);                      \
                for (size_t _i_ = 0; _i_ < _nnn_; _i_++)                \
                        _p_ = stpcpy(_p_, _sss_);                       \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

int split_pair(const char *s, const char *sep, char **ret_first, char **ret_second);

int free_and_strdup(char **p, const char *s);
static inline int free_and_strdup_warn(char **p, const char *s) {
        int r;

        r = free_and_strdup(p, s);
        if (r < 0)
                return log_oom();
        return r;
}
int free_and_strndup(char **p, const char *s, size_t l);

int strdup_to_full(char **ret, const char *src);
static inline int strdup_to(char **ret, const char *src) {
        int r = strdup_to_full(ASSERT_PTR(ret), src);
        return r < 0 ? r : 0;  /* Suppress return value of 1. */
}

bool string_is_safe(const char *p) _pure_;
static inline bool string_is_safe_ascii(const char *p) {
        return ascii_is_valid(p) && string_is_safe(p);
}

DISABLE_WARNING_STRINGOP_TRUNCATION;
static inline void strncpy_exact(char *buf, const char *src, size_t buf_len) {
        strncpy(buf, src, buf_len);
}
REENABLE_WARNING;

/* Like startswith_no_case(), but operates on arbitrary memory blocks.
 * It works only for ASCII strings.
 */
static inline void* memory_startswith_no_case(const void *p, size_t sz, const char *token) {
        assert(token);

        size_t n = strlen(token);
        if (sz < n)
                return NULL;

        assert(p);

        for (size_t i = 0; i < n; i++)
                if (ascii_tolower(((char *)p)[i]) != ascii_tolower(token[i]))
                        return NULL;

        return (uint8_t*) p + n;
}

static inline char* str_realloc(char *p) {
        /* Reallocate *p to actual size. Ignore failure, and return the original string on error. */

        if (!p)
                return NULL;

        return realloc(p, strlen(p) + 1) ?: p;
}

char* string_erase(char *x);

int string_truncate_lines(const char *s, size_t n_lines, char **ret);
int string_extract_line(const char *s, size_t i, char **ret);

int string_contains_word_strv(const char *string, const char *separators, char * const *words, const char **ret_word);
static inline int string_contains_word(const char *string, const char *separators, const char *word) {
        return string_contains_word_strv(string, separators, STRV_MAKE(word), NULL);
}

bool streq_skip_trailing_chars(const char *s1, const char *s2, const char *ok);

char* string_replace_char(char *str, char old_char, char new_char);

typedef enum MakeCStringMode {
        MAKE_CSTRING_REFUSE_TRAILING_NUL,
        MAKE_CSTRING_ALLOW_TRAILING_NUL,
        MAKE_CSTRING_REQUIRE_TRAILING_NUL,
        _MAKE_CSTRING_MODE_MAX,
        _MAKE_CSTRING_MODE_INVALID = -1,
} MakeCStringMode;

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret);

size_t strspn_from_end(const char *str, const char *accept);

char* strdupspn(const char *a, const char *accept);
char* strdupcspn(const char *a, const char *reject);

char* find_line_startswith(const char *haystack, const char *needle);

bool version_is_valid(const char *s);

bool version_is_valid_versionspec(const char *s);

ssize_t strlevenshtein(const char *x, const char *y);

char* strrstr(const char *haystack, const char *needle);
