/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foostrvhfoo
#define foostrvhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdarg.h>
#include <stdbool.h>

#include "macro.h"

char *strv_find(char **l, const char *name);
char *strv_find_prefix(char **l, const char *name);

void strv_free(char **l);
char **strv_copy(char **l) _malloc_;
unsigned strv_length(char **l);

char **strv_merge(char **a, char **b);
char **strv_merge_concat(char **a, char **b, const char *suffix);
char **strv_append(char **l, const char *s);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);

#define strv_contains(l, s) (!!strv_find((l), (s)))

char **strv_new(const char *x, ...) _sentinel_ _malloc_;
char **strv_new_ap(const char *x, va_list ap) _malloc_;

static inline bool strv_isempty(char **l) {
        return !l || !*l;
}

char **strv_split(const char *s, const char *separator) _malloc_;
char **strv_split_quoted(const char *s) _malloc_;

char *strv_join(char **l, const char *separator) _malloc_;

char **strv_env_merge(unsigned n_lists, ...);
char **strv_env_delete(char **x, unsigned n_lists, ...);

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)            \
        for (; (l) && ((s) >= (l)); (s)--)

#endif
