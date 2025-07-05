/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* What characters are special in the shell? */
/* must be escaped outside and inside double-quotes */
#define SHELL_NEED_ESCAPE "\"\\`$"

/* Those that can be escaped or double-quoted.
 *
 * Strictly speaking, ! does not need to be escaped, except in interactive
 * mode, but let's be extra nice to the user and quote ! in case this
 * output is ever used in interactive mode. */
#define SHELL_NEED_QUOTES SHELL_NEED_ESCAPE GLOB_CHARS "'()<>|&;!"

/* Note that we assume control characters would need to be escaped too in
 * addition to the "special" characters listed here, if they appear in the
 * string. Current users disallow control characters. Also '"' shall not
 * be escaped.
 */
#define SHELL_NEED_ESCAPE_POSIX "\\\'"

typedef enum UnescapeFlags {
        UNESCAPE_RELAX      = 1 << 0,
        UNESCAPE_ACCEPT_NUL = 1 << 1,
} UnescapeFlags;

typedef enum ShellEscapeFlags {
        /* The default is to add shell quotes ("") so the shell will consider this a single argument.
         * Tabs and newlines are escaped. */

        SHELL_ESCAPE_POSIX = 1 << 1, /* Use POSIX shell escape syntax (a string enclosed in $'') instead of plain quotes. */
        SHELL_ESCAPE_EMPTY = 1 << 2, /* Format empty arguments as "". */
} ShellEscapeFlags;

int cescape_char(char c, char *buf);
char* cescape_length(const char *s, size_t n) _nonnull_if_nonzero_(1, 2);
static inline char* cescape(const char *s) {
        return cescape_length(s, SIZE_MAX);
}

int cunescape_one(const char *p, size_t length, char32_t *ret, bool *eight_bit, bool accept_nul);

ssize_t cunescape_length_with_prefix(const char *s, size_t length, const char *prefix, UnescapeFlags flags, char **ret);
static inline ssize_t cunescape_length(const char *s, size_t length, UnescapeFlags flags, char **ret) {
        return cunescape_length_with_prefix(s, length, NULL, flags, ret);
}
static inline ssize_t cunescape(const char *s, UnescapeFlags flags, char **ret) {
        return cunescape_length(s, SIZE_MAX, flags, ret);
}

typedef enum XEscapeFlags {
        XESCAPE_8_BIT          = 1 << 0,
        XESCAPE_FORCE_ELLIPSIS = 1 << 1,
} XEscapeFlags;

char* xescape_full(const char *s, const char *bad, size_t console_width, XEscapeFlags flags);
static inline char* xescape(const char *s, const char *bad) {
        return xescape_full(s, bad, SIZE_MAX, 0);
}
char* octescape(const char *s, size_t len);
char* decescape(const char *s, size_t len, const char *bad) _nonnull_if_nonzero_(1, 2);
char* escape_non_printable_full(const char *str, size_t console_width, XEscapeFlags flags);

char* shell_escape(const char *s, const char *bad);
char* shell_maybe_quote(const char *s, ShellEscapeFlags flags);
char* quote_command_line(char * const *argv, ShellEscapeFlags flags);
