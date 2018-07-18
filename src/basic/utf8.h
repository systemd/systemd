/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

#include "macro.h"
#include "missing.h"

#define UTF8_REPLACEMENT_CHARACTER "\xef\xbf\xbd"
#define UTF8_BYTE_ORDER_MARK "\xef\xbb\xbf"

bool unichar_is_valid(char32_t c);

char *utf8_is_valid(const char *s) _pure_;
char *ascii_is_valid(const char *s) _pure_;
char *ascii_is_valid_n(const char *str, size_t len);

bool utf8_is_printable_newline(const char* str, size_t length, bool newline) _pure_;
#define utf8_is_printable(str, length) utf8_is_printable_newline(str, length, true)

char *utf8_escape_invalid(const char *s);
char *utf8_escape_non_printable(const char *str);

size_t utf8_encode_unichar(char *out_utf8, char32_t g);
char *utf16_to_utf8(const void *s, size_t length);

int utf8_encoded_valid_unichar(const char *str);
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar);

static inline bool utf16_is_surrogate(char16_t c) {
        return (0xd800 <= c && c <= 0xdfff);
}

static inline bool utf16_is_trailing_surrogate(char16_t c) {
        return (0xdc00 <= c && c <= 0xdfff);
}

static inline char32_t utf16_surrogate_pair_to_unichar(char16_t lead, char16_t trail) {
                return ((lead - 0xd800) << 10) + (trail - 0xdc00) + 0x10000;
}

size_t utf8_n_codepoints(const char *str);
size_t utf8_console_width(const char *str);
