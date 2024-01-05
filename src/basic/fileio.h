/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

#define LONG_LINE_MAX (1U*1024U*1024U)

typedef enum {
        WRITE_STRING_FILE_CREATE                     = 1 << 0,
        WRITE_STRING_FILE_TRUNCATE                   = 1 << 1,
        WRITE_STRING_FILE_ATOMIC                     = 1 << 2,
        WRITE_STRING_FILE_AVOID_NEWLINE              = 1 << 3,
        WRITE_STRING_FILE_VERIFY_ON_FAILURE          = 1 << 4,
        WRITE_STRING_FILE_VERIFY_IGNORE_NEWLINE      = 1 << 5,
        WRITE_STRING_FILE_SYNC                       = 1 << 6,
        WRITE_STRING_FILE_DISABLE_BUFFER             = 1 << 7,
        WRITE_STRING_FILE_NOFOLLOW                   = 1 << 8,
        WRITE_STRING_FILE_MKDIR_0755                 = 1 << 9,
        WRITE_STRING_FILE_MODE_0600                  = 1 << 10,
        WRITE_STRING_FILE_MODE_0444                  = 1 << 11,
        WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL = 1 << 12,

        /* And before you wonder, why write_string_file_atomic_label_ts() is a separate function instead of just one
           more flag here: it's about linking: we don't want to pull -lselinux into all users of write_string_file()
           and friends. */

} WriteStringFileFlags;

typedef enum {
        READ_FULL_FILE_SECURE              = 1 << 0, /* erase any buffers we employ internally, after use */
        READ_FULL_FILE_UNBASE64            = 1 << 1, /* base64 decode what we read */
        READ_FULL_FILE_UNHEX               = 1 << 2, /* hex decode what we read */
        READ_FULL_FILE_WARN_WORLD_READABLE = 1 << 3, /* if regular file, log at LOG_WARNING level if access mode above 0700 */
        READ_FULL_FILE_CONNECT_SOCKET      = 1 << 4, /* if socket inode, connect to it and read off it */
        READ_FULL_FILE_FAIL_WHEN_LARGER    = 1 << 5, /* fail loading if file is larger than specified size */
} ReadFullFileFlags;

int fdopen_unlocked(int fd, const char *options, FILE **ret);
int take_fdopen_unlocked(int *fd, const char *options, FILE **ret);
FILE* take_fdopen(int *fd, const char *options);
DIR* take_fdopendir(int *dfd);
FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc);
FILE* fmemopen_unlocked(void *buf, size_t size, const char *mode);

int write_string_stream_ts(FILE *f, const char *line, WriteStringFileFlags flags, const struct timespec *ts);
static inline int write_string_stream(FILE *f, const char *line, WriteStringFileFlags flags) {
        return write_string_stream_ts(f, line, flags, NULL);
}
int write_string_file_ts_at(int dir_fd, const char *fn, const char *line, WriteStringFileFlags flags, const struct timespec *ts);
static inline int write_string_file_ts(const char *fn, const char *line, WriteStringFileFlags flags, const struct timespec *ts) {
        return write_string_file_ts_at(AT_FDCWD, fn, line, flags, ts);
}
static inline int write_string_file_at(int dir_fd, const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_ts_at(dir_fd, fn, line, flags, NULL);
}
static inline int write_string_file(const char *fn, const char *line, WriteStringFileFlags flags) {
        return write_string_file_ts(fn, line, flags, NULL);
}

int write_string_filef(const char *fn, WriteStringFileFlags flags, const char *format, ...) _printf_(3, 4);

int read_one_line_file_at(int dir_fd, const char *filename, char **ret);
static inline int read_one_line_file(const char *filename, char **ret) {
        return read_one_line_file_at(AT_FDCWD, filename, ret);
}
int read_full_file_full(int dir_fd, const char *filename, uint64_t offset, size_t size, ReadFullFileFlags flags, const char *bind_name, char **ret_contents, size_t *ret_size);
static inline int read_full_file_at(int dir_fd, const char *filename, char **ret_contents, size_t *ret_size) {
        return read_full_file_full(dir_fd, filename, UINT64_MAX, SIZE_MAX, 0, NULL, ret_contents, ret_size);
}
static inline int read_full_file(const char *filename, char **ret_contents, size_t *ret_size) {
        return read_full_file_full(AT_FDCWD, filename, UINT64_MAX, SIZE_MAX, 0, NULL, ret_contents, ret_size);
}

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size);
int read_virtual_file_at(int dir_fd, const char *filename, size_t max_size, char **ret_contents, size_t *ret_size);
static inline int read_virtual_file(const char *filename, size_t max_size, char **ret_contents, size_t *ret_size) {
        return read_virtual_file_at(AT_FDCWD, filename, max_size, ret_contents, ret_size);
}
static inline int read_full_virtual_file(const char *filename, char **ret_contents, size_t *ret_size) {
        return read_virtual_file(filename, SIZE_MAX, ret_contents, ret_size);
}

int read_full_stream_full(FILE *f, const char *filename, uint64_t offset, size_t size, ReadFullFileFlags flags, char **ret_contents, size_t *ret_size);
static inline int read_full_stream(FILE *f, char **ret_contents, size_t *ret_size) {
        return read_full_stream_full(f, NULL, UINT64_MAX, SIZE_MAX, 0, ret_contents, ret_size);
}

int verify_file_at(int dir_fd, const char *fn, const char *blob, bool accept_extra_nl);
static inline int verify_file(const char *fn, const char *blob, bool accept_extra_nl) {
        return verify_file_at(AT_FDCWD, fn, blob, accept_extra_nl);
}

int executable_is_script(const char *path, char **interpreter);

int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field);

DIR *xopendirat(int dirfd, const char *name, int flags);

typedef enum XfopenFlags {
        XFOPEN_UNLOCKED = 1 << 0, /* call __fsetlocking(FSETLOCKING_BYCALLER) after opened */
        XFOPEN_SOCKET   = 1 << 1, /* also try to open unix socket */
} XfopenFlags;

int xfopenat_full(
                int dir_fd,
                const char *path,
                const char *mode,
                int open_flags,
                XfopenFlags flags,
                const char *bind_name,
                FILE **ret);
static inline int xfopenat(int dir_fd, const char *path, const char *mode, int open_flags, FILE **ret) {
        return xfopenat_full(dir_fd, path, mode, open_flags, 0, NULL, ret);
}
static inline int fopen_unlocked_at(int dir_fd, const char *path, const char *mode, int open_flags, FILE **ret) {
        return xfopenat_full(dir_fd, path, mode, open_flags, XFOPEN_UNLOCKED, NULL, ret);
}
static inline int fopen_unlocked(const char *path, const char *mode, FILE **ret) {
        return fopen_unlocked_at(AT_FDCWD, path, mode, 0, ret);
}

int fdopen_independent(int fd, const char *mode, FILE **ret);

int search_and_open(const char *path, int mode, const char *root, char **search, int *ret_fd, char **ret_path);
static inline int search_and_access(const char *path, int mode, const char *root, char**search, char **ret_path) {
        return search_and_open(path, mode, root, search, NULL, ret_path);
}
int search_and_fopen(const char *path, const char *mode, const char *root, const char **search, FILE **ret_file, char **ret_path);
int search_and_fopen_nulstr(const char *path, const char *mode, const char *root, const char *search, FILE **ret_file, char **ret_path);

int fflush_and_check(FILE *f);
int fflush_sync_and_check(FILE *f);

int write_timestamp_file_atomic(const char *fn, usec_t n);
int read_timestamp_file(const char *fn, usec_t *ret);

int fputs_with_space(FILE *f, const char *s, const char *separator, bool *space);

typedef enum ReadLineFlags {
        READ_LINE_ONLY_NUL  = 1 << 0,
        READ_LINE_IS_A_TTY  = 1 << 1,
        READ_LINE_NOT_A_TTY = 1 << 2,
} ReadLineFlags;

int read_line_full(FILE *f, size_t limit, ReadLineFlags flags, char **ret);

static inline bool file_offset_beyond_memory_size(off_t x) {
        if (x < 0) /* off_t is signed, filter that out */
                return false;
        return (uint64_t) x > (uint64_t) SIZE_MAX;
}

static inline int read_line(FILE *f, size_t limit, char **ret) {
        return read_line_full(f, limit, 0, ret);
}

static inline int read_nul_string(FILE *f, size_t limit, char **ret) {
        return read_line_full(f, limit, READ_LINE_ONLY_NUL, ret);
}

int read_stripped_line(FILE *f, size_t limit, char **ret);

int safe_fgetc(FILE *f, char *ret);

int warn_file_is_world_accessible(const char *filename, struct stat *st, const char *unit, unsigned line);

int fopen_mode_to_flags(const char *mode);
