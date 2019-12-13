/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

typedef enum ExtractFlags {
        EXTRACT_RELAX                    = 1 << 0,
        EXTRACT_CUNESCAPE                = 1 << 1,
        EXTRACT_CUNESCAPE_RELAX          = 1 << 2,
        EXTRACT_UNQUOTE                  = 1 << 3,
        EXTRACT_DONT_COALESCE_SEPARATORS = 1 << 4,
        EXTRACT_RETAIN_ESCAPE            = 1 << 5,
} ExtractFlags;

int extract_first_word(const char **p, char **ret, const char *separators, ExtractFlags flags);
int extract_first_word_and_warn(const char **p, char **ret, const char *separators, ExtractFlags flags, const char *unit, const char *filename, unsigned line, const char *rvalue);
int extract_many_words(const char **p, const char *separators, unsigned flags, ...) _sentinel_;
