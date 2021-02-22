/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

/* The *_extension_release flavours will look for /usr/lib/extension-release/extension-release.NAME
 * in accordance with the OS extension specification, rather than for /usr/lib/ or /etc/os-release. */

int path_is_extension_tree(const char *path, const char *extension);
static inline int path_is_os_tree(const char *path) {
        return path_is_extension_tree(path, NULL);
}

int open_extension_release(const char *root, const char *extension, char **ret_path, int *ret_fd);
static inline int open_os_release(const char *root, char **ret_path, int *ret_fd) {
        return open_extension_release(root, NULL, ret_path, ret_fd);
}

int fopen_extension_release(const char *root, const char *extension, char **ret_path, FILE **ret_file);
static inline int fopen_os_release(const char *root, char **ret_path, FILE **ret_file) {
        return fopen_extension_release(root, NULL, ret_path, ret_file);
}

int parse_extension_release(const char *root, const char *extension, ...) _sentinel_;
int parse_os_release(const char *root, ...) _sentinel_;
int load_extension_release_pairs(const char *root, const char *extension, char ***ret);
int load_os_release_pairs(const char *root, char ***ret);
int load_os_release_pairs_with_prefix(const char *root, const char *prefix, char ***ret);

/* Given an image name (for logging purposes), a set of os-release values from the host
 * and a key-value pair vector of extension-release variables, check that the distro and
 * (system extension level or distro version) match and return 1, and 0 otherwise. */
int extension_release_validate(const char *name, const char *host_os_release_id, const char *host_os_release_version_id, const char *host_os_release_sysext_level, char **extension_release);

/* Parse SYSTEMD_SYSEXT_HIERARCHIES and if not set, return "/usr /opt" */
int parse_env_extension_hierarchies(char ***ret_hierarchies);
