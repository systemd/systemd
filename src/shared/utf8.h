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

const char *utf8_is_valid(const char *s) _pure_;
char *ascii_is_valid(const char *s) _pure_;
char *utf8_escape_invalid(const char *s);

bool utf8_is_printable_newline(const char* str, size_t length, bool newline) _pure_;
_pure_ static inline bool utf8_is_printable(const char* str, size_t length) {
        return utf8_is_printable_newline(str, length, true);
}

char *utf16_to_utf8(const void *s, size_t length);

int utf8_encoded_valid_unichar(const char *str);
int utf8_encoded_to_unichar(const char *str);
