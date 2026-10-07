/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int drop_in_file(
                const char *dir,
                const char *unit,
                unsigned level,
                const char *name,
                char **ret_unit_dir,
                char **ret_path);

int write_drop_in(
                const char *dir,
                const char *unit,
                unsigned level,
                const char *name,
                const char *data);
int write_drop_in_format(
                const char *dir,
                const char *unit,
                unsigned level,
                const char *name,
                const char *format, ...) _printf_(5, 6);

/* The values describe how PID 1 treats an entry of a .wants/, .requires/ or .upholds/ directory. */
typedef enum DependencyEntryType {
        /* The entry is a symlink with a valid unit name. PID 1 adds the dependency. */
        DEPENDENCY_ENTRY_SYMLINK,
        /* The entry resolves to /dev/null or to an empty file. */
        DEPENDENCY_ENTRY_MASK,
        DEPENDENCY_ENTRY_NOT_SYMLINK,
        DEPENDENCY_ENTRY_INVALID_NAME,
        _DEPENDENCY_ENTRY_TYPE_MAX,
        _DEPENDENCY_ENTRY_TYPE_INVALID = -EINVAL,
} DependencyEntryType;

int unit_file_classify_dependency_entry(const char *path, const char *root, DependencyEntryType *ret_type, char **ret_name);

int unit_file_find_dropin_paths(
                const char *original_root,
                char **lookup_path,
                Set *unit_path_cache,
                const char *dir_suffix,
                const char *file_suffix,
                const char *name,
                const Set *aliases,
                char ***ret);
int unit_file_find_dropin_entry(
                const char *original_root,
                char **lookup_path,
                const char *dir_suffix,
                const char *name,
                const Set *aliases,
                const char *entry,
                char **ret);
