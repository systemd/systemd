/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>

#include "macro.h"

int parse_env_filev(FILE *f, const char *fname, va_list ap);
int parse_env_file_fdv(int fd, const char *fname, va_list ap);
int parse_env_file_sentinel(FILE *f, const char *fname, ...) _sentinel_;
#define parse_env_file(f, fname, ...) parse_env_file_sentinel(f, fname, __VA_ARGS__, NULL)
int parse_env_file_fd_sentinel(int fd, const char *fname, ...) _sentinel_;
#define parse_env_file_fd(fd, fname, ...) parse_env_file_fd_sentinel(fd, fname, __VA_ARGS__, NULL)
int load_env_file(FILE *f, const char *fname, char ***ret);
int load_env_file_pairs(FILE *f, const char *fname, char ***ret);
int load_env_file_pairs_fd(int fd, const char *fname, char ***ret);

int merge_env_file(char ***env, FILE *f, const char *fname);

int write_env_file_at(int dir_fd, const char *fname, char **l);
static inline int write_env_file(const char *fname, char **l) {
        return write_env_file_at(AT_FDCWD, fname, l);
}
