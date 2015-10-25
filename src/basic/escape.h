/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/types.h>
#include <inttypes.h>

/* What characters are special in the shell? */
/* must be escaped outside and inside double-quotes */
#define SHELL_NEED_ESCAPE "\"\\`$"
/* can be escaped or double-quoted */
#define SHELL_NEED_QUOTES SHELL_NEED_ESCAPE GLOB_CHARS "'()<>|&;"

typedef enum UnescapeFlags {
        UNESCAPE_RELAX = 1,
} UnescapeFlags;

char *cescape(const char *s);
size_t cescape_char(char c, char *buf);

int cunescape(const char *s, UnescapeFlags flags, char **ret);
int cunescape_length(const char *s, size_t length, UnescapeFlags flags, char **ret);
int cunescape_length_with_prefix(const char *s, size_t length, const char *prefix, UnescapeFlags flags, char **ret);
int cunescape_one(const char *p, size_t length, char *ret, uint32_t *ret_unicode);

char *xescape(const char *s, const char *bad);

char *shell_escape(const char *s, const char *bad);
char *shell_maybe_quote(const char *s);
