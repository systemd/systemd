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
#include <stddef.h>
#include <stdio.h>

#include "macro.h"

int write_string_stream(FILE *f, const char *line);
int write_string_file(const char *fn, const char *line);
int write_string_file_no_create(const char *fn, const char *line);
int write_string_file_atomic(const char *fn, const char *line);

int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);

int verify_one_line_file(const char *fn, const char *line);

int parse_env_file(const char *fname, const char *separator, ...) _sentinel_;
int load_env_file(FILE *f, const char *fname, const char *separator, char ***l);
int load_env_file_pairs(FILE *f, const char *fname, const char *separator, char ***l);

int write_env_file(const char *fname, char **l);

int executable_is_script(const char *path, char **interpreter);

int get_status_field(const char *filename, const char *pattern, char **field);
