/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foopathutilhfoo
#define foopathutilhfoo

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

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

#include "stdbool.h"

bool is_path(const char *p);
char **path_split_and_make_absolute(const char *p);
char *path_get_file_name(const char *p);
int path_get_parent(const char *path, char **parent);
bool path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);
char *path_make_absolute_cwd(const char *p);
char *path_kill_slashes(char *path);
bool path_startswith(const char *path, const char *prefix);
bool path_equal(const char *a, const char *b);

char **path_strv_make_absolute_cwd(char **l);
char **path_strv_canonicalize(char **l);
char **path_strv_remove_empty(char **l);

int path_is_mount_point(const char *path, bool allow_symlink);
int path_is_read_only_fs(const char *path);

#endif
