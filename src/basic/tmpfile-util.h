/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdio.h>

int fopen_temporary_at(int dir_fd, const char *path, FILE **ret_file, char **ret_path);
static inline int fopen_temporary(const char *path, FILE **ret_file, char **ret_path) {
        return fopen_temporary_at(AT_FDCWD, path, ret_file, ret_path);
}

int xmkostempat(int dir_fd, char *pattern);
int mkostempat_safe(int dir_fd, char *pattern);
static inline int mkostemp_safe(char *pattern) {
        return mkostempat_safe(AT_FDCWD, pattern);
}
int fmkostempat_safe(int dir_fd, char *pattern, const char *mode, FILE** ret_file);
static inline int fmkostemp_safe(char *pattern, const char *mode, FILE** ret_file) {
        return fmkostempat_safe(AT_FDCWD, pattern, mode, ret_file);
}

int tempfn_xxxxxx(const char *p, const char *extra, char **ret);
int tempfn_random(const char *p, const char *extra, char **ret);
int tempfn_random_child(const char *p, const char *extra, char **ret);

int open_tmpfile_unlinkable(const char *directory, int flags);
int open_tmpfile_linkable(const char *target, int flags, char **ret_path);
int fopen_tmpfile_linkable(const char *target, int flags, char **ret_path, FILE **ret_file);

int link_tmpfile(int fd, const char *path, const char *target);
int flink_tmpfile(FILE *f, const char *path, const char *target);

int mkdtemp_malloc(const char *template, char **ret);
int mkdtemp_open(const char *template, int flags, char **ret);
