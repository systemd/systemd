/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

bool env_name_is_valid(const char *e);
bool env_value_is_valid(const char *e);
bool env_assignment_is_valid(const char *e);

char *replace_env(const char *format, char **env);
char **replace_env_argv(char **argv, char **env);

bool strv_env_is_valid(char **e);
#define strv_env_clean(l) strv_env_clean_with_callback(l, NULL, NULL)
char **strv_env_clean_with_callback(char **l, void (*invalid_callback)(const char *p, void *userdata), void *userdata);

bool strv_env_name_is_valid(char **l);
bool strv_env_name_or_assignment_is_valid(char **l);

char **strv_env_merge(unsigned n_lists, ...);
char **strv_env_delete(char **x, unsigned n_lists, ...); /* New copy */

char **strv_env_set(char **x, const char *p); /* New copy ... */
char **strv_env_unset(char **l, const char *p); /* In place ... */
char **strv_env_unset_many(char **l, ...) _sentinel_;

char *strv_env_get_n(char **l, const char *name, size_t k) _pure_;
char *strv_env_get(char **x, const char *n) _pure_;

int getenv_bool(const char *p);
