/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdio.h>

int path_is_os_tree(const char *path);

int open_os_release(const char *root, char **ret_path, int *ret_fd);
int fopen_os_release(const char *root, char **ret_path, FILE **ret_file);

int parse_os_release(const char *root, ...) _sentinel_;
int load_os_release_pairs(const char *root, char ***ret);
