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

#include <stdarg.h>
#include <stdbool.h>

#include "macro.h"

char *strv_find(char **l, const char *name) _pure_;
char *strv_find_prefix(char **l, const char *name) _pure_;

void strv_free(char **l);
static inline void strv_freep(char ***l) {
        strv_free(*l);
}

#define _cleanup_strv_free_ _cleanup_(strv_freep)

char **strv_copy(char * const *l);
unsigned strv_length(char * const *l) _pure_;

char **strv_merge(char **a, char **b);
char **strv_merge_concat(char **a, char **b, const char *suffix);
char **strv_append(char **l, const char *s);
int strv_extend(char ***l, const char *value);
int strv_push(char ***l, char *value);

char **strv_remove(char **l, const char *s);
char **strv_remove_prefix(char **l, const char *s);
char **strv_uniq(char **l);

#define strv_contains(l, s) (!!strv_find((l), (s)))

char **strv_new(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);

static inline const char* STRV_IFNOTNULL(const char *x) {
        return x ? x : (const char *) -1;
}

static inline bool strv_isempty(char * const *l) {
        return !l || !*l;
}

char **strv_split(const char *s, const char *separator);
char **strv_split_quoted(const char *s);
char **strv_split_newlines(const char *s);

char *strv_join(char **l, const char *separator);
char *strv_join_quoted(char **l);

char **strv_parse_nulstr(const char *s, size_t l);
char **strv_split_nulstr(const char *s);

bool strv_overlap(char **a, char **b) _pure_;

#define STRV_FOREACH(s, l)                      \
        for ((s) = (l); (s) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)            \
        for (; (l) && ((s) >= (l)); (s)--)

#define STRV_FOREACH_PAIR(x, y, l)               \
        for ((x) = (l), (y) = (x+1); (x) && *(x) && *(y); (x) += 2, (y) = (x + 1))


char **strv_sort(char **l);
void strv_print(char **l);
