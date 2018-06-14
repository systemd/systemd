/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum CopyFlags {
        COPY_REFLINK    = 1 << 0, /* Try to reflink */
        COPY_MERGE      = 1 << 1, /* Merge existing trees with our new one to copy */
        COPY_REPLACE    = 1 << 2, /* Replace an existing file if there's one */
        COPY_SAME_MOUNT = 1 << 3, /* Don't descend recursively into other file systems, across mount point boundaries */
} CopyFlags;

int copy_file_fd(const char *from, int to, CopyFlags copy_flags);
int copy_file(const char *from, const char *to, int open_flags, mode_t mode, unsigned chattr_flags, CopyFlags copy_flags);
int copy_file_atomic(const char *from, const char *to, mode_t mode, unsigned chattr_flags, CopyFlags copy_flags);
int copy_tree(const char *from, const char *to, uid_t override_uid, gid_t override_gid, CopyFlags copy_flags);
int copy_tree_at(int fdf, const char *from, int fdt, const char *to, uid_t override_uid, gid_t override_gid, CopyFlags copy_flags);
int copy_directory_fd(int dirfd, const char *to, CopyFlags copy_flags);
int copy_directory(const char *from, const char *to, CopyFlags copy_flags);
int copy_bytes_full(int fdf, int fdt, uint64_t max_bytes, CopyFlags copy_flags, void **ret_remains, size_t *ret_remains_size);
static inline int copy_bytes(int fdf, int fdt, uint64_t max_bytes, CopyFlags copy_flags) {
        return copy_bytes_full(fdf, fdt, max_bytes, copy_flags, NULL, NULL);
}
int copy_times(int fdf, int fdt);
int copy_xattr(int fdf, int fdt);
