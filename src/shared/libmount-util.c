/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <stdio.h>

#include "alloc-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
#include "stat-util.h"

int libmount_parse(
                const char *path,
                FILE *source,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        /* Older libmount seems to require this. */
        assert(!source || path);

        table = mnt_new_table();
        iter = mnt_new_iter(MNT_ITER_FORWARD);
        if (!table || !iter)
                return -ENOMEM;

        /* If source or path are specified, we use on the functions which ignore utab.
         * Only if both are empty, we use mnt_table_parse_mtab(). */

        if (source)
                r = mnt_table_parse_stream(table, source, path);
        else if (path)
                r = mnt_table_parse_file(table, path);
        else
                r = mnt_table_parse_mtab(table, NULL);
        if (r < 0)
                return r;

        *ret_table = TAKE_PTR(table);
        *ret_iter = TAKE_PTR(iter);
        return 0;
}

/* How many overlays to unpack when checking if the upper layer is a temporary file system. */
#define MAX_NESTED_OVERLAYFS_CHECKS 128

int path_is_temporary_fs_harder(const char *path) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        _cleanup_free_ char *upper = NULL;
        int r;

        /* Check if the specified path is on a temporary filesystem.
         *
         * This is like path_is_temporary_fs(), but supports overlayfs. If the mountpoint is found be an
         * overlay, mount table is parsed to extract the upperdir= option for the mountpoint, and this
         * mountpoint is checked recursively. This recursive check is done up to MAX_NESTED_OVERLAYFS_CHECKS
         * times, in case somebody wants to go crazy and nest overlays.
         */

        for (unsigned tries = 0; tries < MAX_NESTED_OVERLAYFS_CHECKS; tries++) {
                struct statfs s;
                if (statfs(path, &s) < 0)
                        return log_error_errno(errno, "Failed to statfs \"%s\": %m", path);

                if (is_temporary_fs(&s))
                        return true;  /* All good! */

                if (!is_fs_type(&s, OVERLAYFS_SUPER_MAGIC))
                        return false;  /* Not temporary. */

                /* Loop through the mount table, following the mountpoints used as the upper= layer of the
                 * overlayfs. We search backwards through the table, because mountpoints lower in the stack
                 * must be earlier. */

                if (!table) {  /* First round */
                        r = libmount_parse("/proc/self/mountinfo", NULL, &table, &iter);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");
                }

                struct libmnt_fs *fs = mnt_table_find_target(table, path, MNT_ITER_BACKWARD);
                if (!fs)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Failed to parse /proc/self/mountinfo: %m");

                const char *opts = mnt_fs_get_options(fs);

                upper = mfree(upper);
                r = fstab_filter_options(opts, "upperdir\0", NULL, &upper, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to query mount options of \"%s\": %m", path);
                if (r == 0)
                        return false;  /* No upper layer. */

                path = upper;  /* Start next round. */
        }

        return -ELOOP;
}
