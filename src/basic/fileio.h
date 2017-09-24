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

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

typedef enum {
        WRITE_STRING_FILE_CREATE = 1<<0,
        WRITE_STRING_FILE_ATOMIC = 1<<1,
        WRITE_STRING_FILE_AVOID_NEWLINE = 1<<2,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE = 1<<3,
        WRITE_STRING_FILE_SYNC = 1<<4,
} WriteStringFileFlags;

int write_string_stream_ts(FILE *f, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_stream(FILE *f, const char *line, WriteStringFileFlags flags) {
        return write_string_stream_ts(f, line, flags, NULL);
}
int write_string_file_ts(const char *fn, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_file(const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_ts(fn, line, flags, NULL);
}

int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);

int verify_file(const char *fn, const char *blob, bool accept_extra_nl);

int parse_env_file(const char *fname, const char *separator, ...) _sentinel_;
int load_env_file(FILE *f, const char *fname, const char *separator, char ***l);
int load_env_file_pairs(FILE *f, const char *fname, const char *separator, char ***l);

int merge_env_file(char ***env, FILE *f, const char *fname);

int write_env_file(const char *fname, char **l);

int executable_is_script(const char *path, char **interpreter);

int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field);

DIR *xopendirat(int dirfd, const char *name, int flags);

int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **_f);
int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **_f);

#define FOREACH_LINE(line, f, on_error)                         \
        for (;;)                                                \
                if (!fgets(line, sizeof(line), f)) {            \
                        if (ferror(f)) {                        \
                                on_error;                       \
                        }                                       \
                        break;                                  \
                } else

int fflush_and_check(FILE *f);
int fflush_sync_and_check(FILE *f);

int fopen_temporary(const char *path, FILE **_f, char **_temp_path);
int mkostemp_safe(char *pattern);

int tempfn_xxxxxx(const char *p, const char *extra, char **ret);
int tempfn_random(const char *p, const char *extra, char **ret);
int tempfn_random_child(const char *p, const char *extra, char **ret);

int write_timestamp_file_atomic(const char *fn, usec_t n);
int read_timestamp_file(const char *fn, usec_t *ret);

int fputs_with_space(FILE *f, const char *s, const char *separator, bool *space);

int open_tmpfile_unlinkable(const char *directory, int flags);
int open_tmpfile_linkable(const char *target, int flags, char **ret_path);
int open_serialization_fd(const char *ident);

int link_tmpfile(int fd, const char *path, const char *target);

int read_nul_string(FILE *f, char **ret);

int mkdtemp_malloc(const char *template, char **ret);

int read_line(FILE *f, size_t limit, char **ret);
