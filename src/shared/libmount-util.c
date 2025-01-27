/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "libmount-util.h"

int libmount_parse_full(
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

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs) {
        int r;

        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter_children = NULL;
        iter_children = mnt_new_iter(MNT_ITER_FORWARD);
        if (!iter_children)
                return log_oom();

        /* We care only whether it exists, it is unused */
        _unused_ struct libmnt_fs *child;
        r = mnt_table_next_child_fs(table, iter_children, fs, &child);
        if (r < 0)
                return r;

        return r == 1;
}
