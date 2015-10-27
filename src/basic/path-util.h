/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include <stdbool.h>

#include "macro.h"
#include "time-util.h"

#define DEFAULT_PATH_NORMAL "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
#define DEFAULT_PATH_SPLIT_USR DEFAULT_PATH_NORMAL ":/sbin:/bin"

#ifdef HAVE_SPLIT_USR
#  define DEFAULT_PATH DEFAULT_PATH_SPLIT_USR
#else
#  define DEFAULT_PATH DEFAULT_PATH_NORMAL
#endif

bool is_path(const char *p) _pure_;
int path_split_and_make_absolute(const char *p, char ***ret);
bool path_is_absolute(const char *p) _pure_;
char* path_make_absolute(const char *p, const char *prefix);
int path_make_absolute_cwd(const char *p, char **ret);
int path_make_relative(const char *from_dir, const char *to_path, char **_r);
char* path_kill_slashes(char *path);
char* path_startswith(const char *path, const char *prefix) _pure_;
int path_compare(const char *a, const char *b) _pure_;
bool path_equal(const char *a, const char *b) _pure_;
bool path_equal_or_files_same(const char *a, const char *b);
char* path_join(const char *root, const char *path, const char *rest);

int path_strv_make_absolute_cwd(char **l);
char** path_strv_resolve(char **l, const char *prefix);
char** path_strv_resolve_uniq(char **l, const char *prefix);

int find_binary(const char *name, char **filename);

bool paths_check_timestamp(const char* const* paths, usec_t *paths_ts_usec, bool update);

int fsck_exists(const char *fstype);
int mkfs_exists(const char *fstype);

/* Iterates through the path prefixes of the specified path, going up
 * the tree, to root. Also returns "" (and not "/"!) for the root
 * directory. Excludes the specified directory itself */
#define PATH_FOREACH_PREFIX(prefix, path) \
        for (char *_slash = ({ path_kill_slashes(strcpy(prefix, path)); streq(prefix, "/") ? NULL : strrchr(prefix, '/'); }); _slash && ((*_slash = 0), true); _slash = strrchr((prefix), '/'))

/* Same as PATH_FOREACH_PREFIX but also includes the specified path itself */
#define PATH_FOREACH_PREFIX_MORE(prefix, path) \
        for (char *_slash = ({ path_kill_slashes(strcpy(prefix, path)); if (streq(prefix, "/")) prefix[0] = 0; strrchr(prefix, 0); }); _slash && ((*_slash = 0), true); _slash = strrchr((prefix), '/'))

char *prefix_root(const char *root, const char *path);

/* Similar to prefix_root(), but returns an alloca() buffer, or
 * possibly a const pointer into the path parameter */
#define prefix_roota(root, path)                                        \
        ({                                                              \
                const char* _path = (path), *_root = (root), *_ret;     \
                char *_p, *_n;                                          \
                size_t _l;                                              \
                while (_path[0] == '/' && _path[1] == '/')              \
                        _path ++;                                       \
                if (isempty(_root) || path_equal(_root, "/"))           \
                        _ret = _path;                                   \
                else {                                                  \
                        _l = strlen(_root) + 1 + strlen(_path) + 1;     \
                        _n = alloca(_l);                                \
                        _p = stpcpy(_n, _root);                         \
                        while (_p > _n && _p[-1] == '/')                \
                                _p--;                                   \
                        if (_path[0] != '/')                            \
                                *(_p++) = '/';                          \
                        strcpy(_p, _path);                              \
                        _ret = _n;                                      \
                }                                                       \
                _ret;                                                   \
        })

int parse_path_argument_and_warn(const char *path, bool suppress_root, char **arg);

char* dirname_malloc(const char *path);

bool filename_is_valid(const char *p) _pure_;
bool path_is_safe(const char *p) _pure_;

char *file_in_same_dir(const char *path, const char *filename);

bool hidden_file_allow_backup(const char *filename);
bool hidden_file(const char *filename) _pure_;

bool is_device_path(const char *path);
