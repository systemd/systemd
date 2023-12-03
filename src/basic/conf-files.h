/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "macro.h"

enum {
        CONF_FILES_EXECUTABLE    = 1 << 0,
        CONF_FILES_REGULAR       = 1 << 1,
        CONF_FILES_DIRECTORY     = 1 << 2,
        CONF_FILES_BASENAME      = 1 << 3,
        CONF_FILES_FILTER_MASKED = 1 << 4,
};

int conf_files_list(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dir);
int conf_files_list_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dir);
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, unsigned flags, const char* const* dirs);
int conf_files_list_strv_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char * const *dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, unsigned flags, const char *dirs);
int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, unsigned flags, const char *dirs);
int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path);
int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***files,
                char **replace_file);
int conf_files_list_dropins(
                char ***ret,
                const char *dropin_dirname,
                const char *root,
                const char * const *dirs);

typedef int parse_line_t(
                void *data,
                const char *fname,
                unsigned line,
                const char *buffer,
                bool *invalid_config);

int conf_file_read(
                const char *root,
                const char **config_dirs,
                const char *fn,
                parse_line_t parse_line,
                void *userdata,
                bool ignore_enoent,
                bool *invalid_config);
