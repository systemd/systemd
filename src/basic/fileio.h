/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

typedef enum {
        WRITE_STRING_FILE_CREATE            = 1 << 0,
        WRITE_STRING_FILE_ATOMIC            = 1 << 1,
        WRITE_STRING_FILE_AVOID_NEWLINE     = 1 << 2,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE = 1 << 3,
        WRITE_STRING_FILE_SYNC              = 1 << 4,
        WRITE_STRING_FILE_DISABLE_BUFFER    = 1 << 5,

        /* And before you wonder, why write_string_file_atomic_label_ts() is a separate function instead of just one
           more flag here: it's about linking: we don't want to pull -lselinux into all users of write_string_file()
           and friends. */

} WriteStringFileFlags;

int write_string_stream_ts(FILE *f, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_stream(FILE *f, const char *line, WriteStringFileFlags flags) {
        return write_string_stream_ts(f, line, flags, NULL);
}
int write_string_file_ts(const char *fn, const char *line, WriteStringFileFlags flags, struct timespec *ts);
static inline int write_string_file(const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_ts(fn, line, flags, NULL);
}

int write_string_filef(const char *fn, WriteStringFileFlags flags, const char *format, ...) _printf_(3, 4);

int read_one_line_file(const char *fn, char **line);
int read_full_file(const char *fn, char **contents, size_t *size);
int read_full_stream(FILE *f, char **contents, size_t *size);

int verify_file(const char *fn, const char *blob, bool accept_extra_nl);

int parse_env_filev(FILE *f, const char *fname, const char *separator, va_list ap);
int parse_env_file(FILE *f, const char *fname, const char *separator, ...) _sentinel_;
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
