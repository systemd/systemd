/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>

#include "macro.h"

#define UTF8_REPLACEMENT_CHARACTER "\xef\xbf\xbd"

bool unichar_is_valid(uint32_t c);

const char *utf8_is_valid(const char *s) _pure_;
char *ascii_is_valid(const char *s) _pure_;

bool utf8_is_printable_newline(const char* str, size_t length, bool newline) _pure_;
#define utf8_is_printable(str, length) utf8_is_printable_newline(str, length, true)

char *utf8_escape_invalid(const char *s);
char *utf8_escape_non_printable(const char *str);

size_t utf8_encode_unichar(char *out_utf8, uint32_t g);
char *utf16_to_utf8(const void *s, size_t length);

int utf8_encoded_valid_unichar(const char *str);
int utf8_encoded_to_unichar(const char *str);

static inline bool utf16_is_surrogate(uint16_t c) {
        return (0xd800 <= c && c <= 0xdfff);
}

static inline bool utf16_is_trailing_surrogate(uint16_t c) {
        return (0xdc00 <= c && c <= 0xdfff);
}

static inline uint32_t utf16_surrogate_pair_to_unichar(uint16_t lead, uint16_t trail) {
                return ((lead - 0xd800) << 10) + (trail - 0xdc00) + 0x10000;
}
