/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "time-util.h"

typedef enum ImageClass {
        IMAGE_MACHINE,
        IMAGE_PORTABLE,
        IMAGE_SYSEXT,
        IMAGE_CONFEXT,
        _IMAGE_CLASS_MAX,
        _IMAGE_CLASS_INVALID = -EINVAL,
} ImageClass;

const char* image_class_to_string(ImageClass cl) _const_;
ImageClass image_class_from_string(const char *s) _pure_;

/* The *_extension_release flavours will look for /usr/lib/extension-release/extension-release.NAME
 * in accordance with the OS extension specification, rather than for /usr/lib/ or /etc/os-release. */

bool image_name_is_valid(const char *s) _pure_;

int path_is_extension_tree(ImageClass image_class, const char *path, const char *extension, bool relax_extension_release_check);
static inline int path_is_os_tree(const char *path) {
        return path_is_extension_tree(_IMAGE_CLASS_INVALID, path, NULL, false);
}

int open_extension_release(const char *root, ImageClass image_class, const char *extension, bool relax_extension_release_check, char **ret_path, int *ret_fd);
static inline int open_os_release(const char *root, char **ret_path, int *ret_fd) {
        return open_extension_release(root, _IMAGE_CLASS_INVALID, NULL, false, ret_path, ret_fd);
}

int _parse_extension_release(const char *root, ImageClass image_class, bool relax_extension_release_check, const char *extension, ...) _sentinel_;
int _parse_os_release(const char *root, ...) _sentinel_;
#define parse_extension_release(root, image_class, extension, relax_extension_release_check, ...) _parse_extension_release(root, image_class, relax_extension_release_check, extension, __VA_ARGS__, NULL)
#define parse_os_release(root, ...) _parse_os_release(root, __VA_ARGS__, NULL)

int load_extension_release_pairs(const char *root, ImageClass image_class, const char *extension, bool relax_extension_release_check, char ***ret);
static inline int load_os_release_pairs(const char *root, char ***ret) {
        return load_extension_release_pairs(root, _IMAGE_CLASS_INVALID, NULL, false, ret);
}
int load_os_release_pairs_with_prefix(const char *root, const char *prefix, char ***ret);

int os_release_support_ended(const char *support_end, bool quiet, usec_t *ret_eol);

const char *os_release_pretty_name(const char *pretty_name, const char *name);
