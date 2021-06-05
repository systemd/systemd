/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

typedef enum ExtractFlags {
        EXTRACT_RELAX                    = 1 << 0, /* Allow unbalanced quote and eat up trailing backslash. */
        EXTRACT_CUNESCAPE                = 1 << 1, /* Unescape known escape sequences. */
        EXTRACT_UNESCAPE_RELAX           = 1 << 2, /* Allow and keep unknown escape sequences, allow and keep trailing backslash. */
        EXTRACT_UNESCAPE_SEPARATORS      = 1 << 3, /* Unescape separators (those specified, or whitespace by default). */
        EXTRACT_UNQUOTE                  = 1 << 4, /* Remove quoting with "" and ''. */
        EXTRACT_DONT_COALESCE_SEPARATORS = 1 << 5, /* Don't treat multiple adjacent separators as one */
        EXTRACT_RETAIN_ESCAPE            = 1 << 6, /* Treat escape character '\' as any other character without special meaning */

        /* Note that if no flags are specified, escaped escape characters will be silently stripped. */
} ExtractFlags;

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags);
int extract_first_word_and_warn(const char **p, char **ret, const char *separators, ExtractFlags flags, const char *unit, const char *filename, unsigned line, const char *rvalue);
int extract_many_words(const char **p, const char *separators, unsigned flags, ...) _sentinel_;
