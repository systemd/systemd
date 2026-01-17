/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "forward.h"

typedef enum ConfFilesFlags {
        CONF_FILES_EXECUTABLE               = 1 << 0, /* inode must be marked executable */
        CONF_FILES_REGULAR                  = 1 << 1, /* inode must be regular file */
        CONF_FILES_DIRECTORY                = 1 << 2, /* inode must be directory */
        CONF_FILES_BASENAME                 = 1 << 3, /* only return basename of file, not full path */
        CONF_FILES_FILTER_MASKED_BY_SYMLINK = 1 << 4, /* implement /dev/null symlink based masking */
        CONF_FILES_FILTER_MASKED_BY_EMPTY   = 1 << 5, /* implement masking by empty file */
        CONF_FILES_FILTER_MASKED            = CONF_FILES_FILTER_MASKED_BY_SYMLINK | CONF_FILES_FILTER_MASKED_BY_EMPTY,
        CONF_FILES_TRUNCATE_SUFFIX          = 1 << 6, /* truncate specified suffix from return filename or path */
} ConfFilesFlags;

typedef struct ConfFile {
        char *name;          /* name of a file found in config directories */
        char *result;        /* resolved config directory with the original file name found in the directory */
        char *original_path; /* original config directory with the original file name found in the directory */
        char *resolved_path; /* fully resolved path, where the filename part of the path may be different from the original name */
        int fd;              /* O_PATH fd to resolved_path, -EBADF if the resolved_path does not exist */
        struct stat st;      /* stat of the file. */
} ConfFile;

ConfFile* conf_file_free(ConfFile *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(ConfFile*, conf_file_free);
void conf_file_free_many(ConfFile **array, size_t n);

int conf_file_new_at(const char *path, int rfd, ConfFilesFlags flags, ConfFile **ret);
int conf_file_new(const char *path, const char *root, ConfFilesFlags flags, ConfFile **ret);

int conf_files_list(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dir);
int conf_files_list_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dir);
int conf_files_list_strv(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char* const* dirs);
int conf_files_list_strv_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char * const *dirs);
int conf_files_list_nulstr(char ***ret, const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs);
int conf_files_list_nulstr_at(char ***ret, const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs);

int conf_files_list_full(const char *suffix, const char *root, ConfFilesFlags flags, const char *dir, ConfFile ***ret_files, size_t *ret_n_files);
int conf_files_list_at_full(const char *suffix, int rfd, ConfFilesFlags flags, const char *dir, ConfFile ***ret_files, size_t *ret_n_files);
int conf_files_list_strv_full(const char *suffix, const char *root, ConfFilesFlags flags, const char * const *dirs, ConfFile ***ret_files, size_t *ret_n_files);
int conf_files_list_strv_at_full(const char *suffix, int rfd, ConfFilesFlags flags, const char * const *dirs, ConfFile ***ret_files, size_t *ret_n_files);
int conf_files_list_nulstr_full(const char *suffix, const char *root, ConfFilesFlags flags, const char *dirs, ConfFile ***ret_files, size_t *ret_n_files);
int conf_files_list_nulstr_at_full(const char *suffix, int rfd, ConfFilesFlags flags, const char *dirs, ConfFile ***ret_files, size_t *ret_n_files);

int conf_files_list_with_replacement(
                const char *root,
                char **config_dirs,
                const char *replacement,
                char ***ret_files,
                char **ret_inserted);
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
