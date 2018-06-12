/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <alloca.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "macro.h"

/* What is interpreted as whitespace? */
#define WHITESPACE        " \t\n\r"
#define NEWLINE           "\n\r"
#define QUOTES            "\"\'"
#define COMMENTS          "#;"
#define GLOB_CHARS        "*?["
#define DIGITS            "0123456789"
#define LOWERCASE_LETTERS "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS           LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL    LETTERS DIGITS
#define HEXDIGITS         DIGITS "abcdefABCDEF"

#define streq(a,b) (strcmp((a),(b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define strcaseeq(a,b) (strcasecmp((a),(b)) == 0)
#define strncaseeq(a, b, n) (strncasecmp((a), (b), (n)) == 0)

int strcmp_ptr(const char *a, const char *b) _pure_;

static inline bool streq_ptr(const char *a, const char *b) {
        return strcmp_ptr(a, b) == 0;
}

static inline const char* strempty(const char *s) {
        return s ?: "";
}

static inline const char* strnull(const char *s) {
        return s ?: "(null)";
}

static inline const char *strna(const char *s) {
        return s ?: "n/a";
}

static inline bool isempty(const char *p) {
        return !p || !p[0];
}

static inline const char *empty_to_null(const char *p) {
        return isempty(p) ? NULL : p;
}

static inline const char *empty_to_dash(const char *str) {
        return isempty(str) ? "-" : str;
}

static inline char *startswith(const char *s, const char *prefix) {
        size_t l;

        l = strlen(prefix);
        if (strncmp(s, prefix, l) == 0)
                return (char*) s + l;

        return NULL;
}

static inline char *startswith_no_case(const char *s, const char *prefix) {
        size_t l;

        l = strlen(prefix);
        if (strncasecmp(s, prefix, l) == 0)
                return (char*) s + l;

        return NULL;
}

char *endswith(const char *s, const char *postfix) _pure_;
char *endswith_no_case(const char *s, const char *postfix) _pure_;

char *first_word(const char *s, const char *word) _pure_;

const char* split(const char **state, size_t *l, const char *separator, bool quoted);

#define FOREACH_WORD(word, length, s, state)                            \
        _FOREACH_WORD(word, length, s, WHITESPACE, false, state)

#define FOREACH_WORD_SEPARATOR(word, length, s, separator, state)       \
        _FOREACH_WORD(word, length, s, separator, false, state)

#define _FOREACH_WORD(word, length, s, separator, quoted, state)        \
        for ((state) = (s), (word) = split(&(state), &(length), (separator), (quoted)); (word); (word) = split(&(state), &(length), (separator), (quoted)))

char *strappend(const char *s, const char *suffix);
char *strnappend(const char *s, const char *suffix, size_t length);

char *strjoin_real(const char *x, ...) _sentinel_;
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                size_t _len_ = 0;                                          \
                size_t _i_;                                           \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = alloca(_len_ + 1);                          \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

char *strstrip(char *s);
char *delete_chars(char *s, const char *bad);
char *delete_trailing_chars(char *s, const char *bad);
char *truncate_nl(char *s);

static inline char *skip_leading_chars(const char *s, const char *bad) {

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        return (char*) s + strspn(s, bad);
}

char ascii_tolower(char x);
char *ascii_strlower(char *s);
char *ascii_strlower_n(char *s, size_t n);

char ascii_toupper(char x);
char *ascii_strupper(char *s);

int ascii_strcasecmp_n(const char *a, const char *b, size_t n);
int ascii_strcasecmp_nn(const char *a, size_t n, const char *b, size_t m);

bool chars_intersect(const char *a, const char *b) _pure_;

static inline bool _pure_ in_charset(const char *s, const char* charset) {
        assert(s);
        assert(charset);
        return s[strspn(s, charset)] == '\0';
}

bool string_has_cc(const char *p, const char *ok) _pure_;

char *ellipsize_mem(const char *s, size_t old_length_bytes, size_t new_length_columns, unsigned percent);
static inline char *ellipsize(const char *s, size_t length, unsigned percent) {
        return ellipsize_mem(s, strlen(s), length, percent);
}

char *cellescape(char *buf, size_t len, const char *s);

/* This limit is arbitrary, enough to give some idea what the string contains */
#define CELLESCAPE_DEFAULT_LENGTH 64

bool nulstr_contains(const char *nulstr, const char *needle);

char* strshorten(char *s, size_t l);

char *strreplace(const char *text, const char *old_string, const char *new_string);

char *strip_tab_ansi(char **ibuf, size_t *_isz, size_t highlight[2]);

char *strextend_with_separator(char **x, const char *separator, ...) _sentinel_;

#define strextend(x, ...) strextend_with_separator(x, NULL, __VA_ARGS__)

char *strrep(const char *s, unsigned n);

int split_pair(const char *s, const char *sep, char **l, char **r);

int free_and_strdup(char **p, const char *s);

/* Normal memmem() requires haystack to be nonnull, which is annoying for zero-length buffers */
static inline void *memmem_safe(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {

        if (needlelen <= 0)
                return (void*) haystack;

        if (haystacklen < needlelen)
                return NULL;

        assert(haystack);
        assert(needle);

        return memmem(haystack, haystacklen, needle, needlelen);
}

#if !HAVE_EXPLICIT_BZERO
void explicit_bzero(void *p, size_t l);
#endif

char *string_erase(char *x);

char *string_free_erase(char *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(char *, string_free_erase);
#define _cleanup_string_free_erase_ _cleanup_(string_free_erasep)

bool string_is_safe(const char *p) _pure_;

static inline size_t strlen_ptr(const char *s) {
        if (!s)
                return 0;

        return strlen(s);
}

/* Like startswith(), but operates on arbitrary memory blocks */
static inline void *memory_startswith(const void *p, size_t sz, const char *token) {
        size_t n;

        assert(token);

        n = strlen(token);
        if (sz < n)
                return NULL;

        assert(p);

        if (memcmp(p, token, n) != 0)
                return NULL;

        return (uint8_t*) p + n;
}
