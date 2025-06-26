/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum ConfFilesFlags {
        CONF_FILES_EXECUTABLE               = 1 << 0,
        CONF_FILES_REGULAR                  = 1 << 1,
        CONF_FILES_DIRECTORY                = 1 << 2,
        CONF_FILES_BASENAME                 = 1 << 3,
        CONF_FILES_FILTER_MASKED_BY_SYMLINK = 1 << 4,
        CONF_FILES_FILTER_MASKED_BY_EMPTY   = 1 << 5,
        CONF_FILES_FILTER_MASKED            = CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_FILTER_MASKED_BY_EMPTY,
} ConfFilesFlags;

int conf_files_list(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dir);
int conf_files_list_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dir);
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char* const* dirs);
int conf_files_list_strv_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char * const *dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs);
int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs);
int conf_files_insert(char ***strv, const char *root, char **dirs, const char *path, char **ret_inserted);
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
                const char *fname,
                unsigned line,
                const char *buffer,
                bool *invalid_config,
                void *userdata);

int conf_file_read(
                const char *root,
                const char **config_dirs,
                const char *fn,
                parse_line_t parse_line,
                void *userdata,
                bool ignore_enoent,
                bool *invalid_config);
