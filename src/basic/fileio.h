/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

#define LONG_LINE_MAX (1U*1024U*1024U)

typedef enum {
        WRITE_STRING_FILE_CREATE            = 1 << 0,
        WRITE_STRING_FILE_ATOMIC            = 1 << 1,
        WRITE_STRING_FILE_AVOID_NEWLINE     = 1 << 2,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE = 1 << 3,
        WRITE_STRING_FILE_SYNC              = 1 << 4,
        WRITE_STRING_FILE_DISABLE_BUFFER    = 1 << 5,
        WRITE_STRING_FILE_NOFOLLOW          = 1 << 6,

        /* And before you wonder, why write_string_file_atomic_label_ts() is a separate function instead of just one
           more flag here: it's about linking: we don't want to pull -lselinux into all users of write_string_file()
           and friends. */

} WriteStringFileFlags;

typedef enum {
        READ_FULL_FILE_SECURE   = 1 << 0,
        READ_FULL_FILE_UNBASE64 = 1 << 1,
} ReadFullFileFlags;

int write_string_stream_ts(FILE *f, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_stream(FILE *f, const char *line, WriteStringFileFlags flags) {
        return write_string_stream_ts(f, line, flags, NULL);
}
int write_string_file_ts(const char *fn, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_file(const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_ts(fn, line, flags, NULL);
}

int write_string_filef(const char *fn, WriteStringFileFlags flags, const char *format, ...) _printf_(3, 4);

int read_one_line_file(const char *filename, char **line);
int read_full_file_full(const char *filename, ReadFullFileFlags flags, char **contents, size_t *size);
static inline int read_full_file(const char *filename, char **contents, size_t *size) {
        return read_full_file_full(filename, 0, contents, size);
}
int read_full_stream_full(FILE *f, const char *filename, ReadFullFileFlags flags, char **contents, size_t *size);
static inline int read_full_stream(FILE *f, char **contents, size_t *size) {
        return read_full_stream_full(f, NULL, 0, contents, size);
}

int verify_file(const char *fn, const char *blob, bool accept_extra_nl);

int executable_is_script(const char *path, char **interpreter);

int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field);

DIR *xopendirat(int dirfd, const char *name, int flags);

int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **_f);
int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **_f);

int fflush_and_check(FILE *f);
int fflush_sync_and_check(FILE *f);

int write_timestamp_file_atomic(const char *fn, usec_t n);
int read_timestamp_file(const char *fn, usec_t *ret);

int fputs_with_space(FILE *f, const char *s, const char *separator, bool *space);

typedef enum ReadLineFlags {
        READ_LINE_ONLY_NUL = 1 << 0,
} ReadLineFlags;

int read_line_full(FILE *f, size_t limit, ReadLineFlags flags, char **ret);

static inline int read_line(FILE *f, size_t limit, char **ret) {
        return read_line_full(f, limit, 0, ret);
}

static inline int read_nul_string(FILE *f, size_t limit, char **ret) {
        return read_line_full(f, limit, READ_LINE_ONLY_NUL, ret);
}

int safe_fgetc(FILE *f, char *ret);

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line);
