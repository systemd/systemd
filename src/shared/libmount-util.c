/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libmount-util.h"
#include "log.h"

#if HAVE_LIBMOUNT

#include <stdio.h>

#include "fstab-util.h"
#include "mountpoint-util.h"

DLSYM_PROTOTYPE(mnt_free_iter) = NULL;
DLSYM_PROTOTYPE(mnt_free_table) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_fs_options) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_fstype) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_id) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_option) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_options) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_passno) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_propagation) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_source) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_target) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_vfs_options) = NULL;
DLSYM_PROTOTYPE(mnt_get_builtin_optmap) = NULL;
DLSYM_PROTOTYPE(mnt_init_debug) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_enable_kernel) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_enable_userspace) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_get_fd) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_next_change) = NULL;
DLSYM_PROTOTYPE(mnt_new_iter) = NULL;
DLSYM_PROTOTYPE(mnt_new_monitor) = NULL;
DLSYM_PROTOTYPE(mnt_new_table) = NULL;
DLSYM_PROTOTYPE(mnt_optstr_get_flags) = NULL;
DLSYM_PROTOTYPE(mnt_table_find_devno) = NULL;
DLSYM_PROTOTYPE(mnt_table_find_target) = NULL;
DLSYM_PROTOTYPE(mnt_table_next_child_fs) = NULL;
DLSYM_PROTOTYPE(mnt_table_next_fs) = NULL;
DLSYM_PROTOTYPE(mnt_table_parse_file) = NULL;
DLSYM_PROTOTYPE(mnt_table_parse_mtab) = NULL;
DLSYM_PROTOTYPE(mnt_table_parse_stream) = NULL;
DLSYM_PROTOTYPE(mnt_table_parse_swaps) = NULL;
DLSYM_PROTOTYPE(mnt_unref_monitor) = NULL;

int libmount_parse_full(
                const char *path,
                FILE *source,
                int direction,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        /* Older libmount seems to require this. */
        assert(!source || path);
        assert(IN_SET(direction, MNT_ITER_FORWARD, MNT_ITER_BACKWARD));
        assert(ret_table);
        assert(ret_iter);

        r = dlopen_libmount(LOG_DEBUG);
        if (r < 0)
                return r;

        table = sym_mnt_new_table();
        iter = sym_mnt_new_iter(direction);
        if (!table || !iter)
                return -ENOMEM;

        /* If source or path are specified, we use on the functions which ignore utab.
         * Only if both are empty, we use mnt_table_parse_mtab(). */

        if (source)
                r = sym_mnt_table_parse_stream(table, source, path);
        else if (path)
                r = sym_mnt_table_parse_file(table, path);
        else
                r = sym_mnt_table_parse_mtab(table, NULL);
        if (r < 0)
                return r;

        *ret_table = TAKE_PTR(table);
        *ret_iter = TAKE_PTR(iter);
        return 0;
}

int libmount_parse_fstab(
        struct libmnt_table **ret_table,
        struct libmnt_iter **ret_iter) {

        return libmount_parse_full(fstab_path(), NULL, MNT_ITER_FORWARD, ret_table, ret_iter);
}

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs) {
        int r;

        assert(table);

        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter_children = NULL;
        iter_children = sym_mnt_new_iter(MNT_ITER_FORWARD);
        if (!iter_children)
                return log_oom();

        /* We care only whether it exists, it is unused */
        _unused_ struct libmnt_fs *child;
        r = sym_mnt_table_next_child_fs(table, iter_children, fs, &child);
        if (r < 0)
                return r;

        return r == 1;
}

/* Checks whether 'fs' (an entry from a parsed mountinfo table) still refers to the file system currently
 * reachable at its own target path. This can be false if something else has since been mounted on top of
 * it, shadowing it: opening 'path' would then resolve to whatever is currently on top, not to 'fs' itself.
 *
 * Returns 1 if the mount IDs match (i.e. 'fs' is still the topmost, reachable mount at its path), 0 if
 * they don't (with a debug log message explaining why), and a negative errno otherwise. */
int libmount_fs_id_matches_path(struct libmnt_fs *fs, const char *path) {
        int id1, id2, r;

        assert(fs);
        assert(path);

        id1 = sym_mnt_fs_get_id(fs);

        r = path_get_mnt_id(path, &id2);
        if (r < 0)
                return log_debug_errno(r, "Failed to get mount ID of '%s': %m", path);

        if (id1 != id2) {
                log_debug("The mount IDs of '%s' obtained by libmount and path_get_mnt_id() are different (%i vs %i).",
                          path, id1, id2);
                return 0;
        }

        return 1;
}

#endif

int dlopen_libmount(int log_level) {
#if HAVE_LIBMOUNT
        static void *libmount_dl = NULL;

        LIBMOUNT_NOTE(suggested);

        return dlopen_many_sym_or_warn(
                        &libmount_dl,
                        "libmount.so.1",
                        log_level,
                        DLSYM_ARG(mnt_free_iter),
                        DLSYM_ARG(mnt_free_table),
                        DLSYM_ARG(mnt_fs_get_fs_options),
                        DLSYM_ARG(mnt_fs_get_fstype),
                        DLSYM_ARG(mnt_fs_get_id),
                        DLSYM_ARG(mnt_fs_get_option),
                        DLSYM_ARG(mnt_fs_get_options),
                        DLSYM_ARG(mnt_fs_get_passno),
                        DLSYM_ARG(mnt_fs_get_propagation),
                        DLSYM_ARG(mnt_fs_get_source),
                        DLSYM_ARG(mnt_fs_get_target),
                        DLSYM_ARG(mnt_fs_get_vfs_options),
                        DLSYM_ARG(mnt_get_builtin_optmap),
                        DLSYM_ARG(mnt_init_debug),
                        DLSYM_ARG(mnt_monitor_enable_kernel),
                        DLSYM_ARG(mnt_monitor_enable_userspace),
                        DLSYM_ARG(mnt_monitor_get_fd),
                        DLSYM_ARG(mnt_monitor_next_change),
                        DLSYM_ARG(mnt_new_iter),
                        DLSYM_ARG(mnt_new_monitor),
                        DLSYM_ARG(mnt_new_table),
                        DLSYM_ARG(mnt_optstr_get_flags),
                        DLSYM_ARG(mnt_table_find_devno),
                        DLSYM_ARG(mnt_table_find_target),
                        DLSYM_ARG(mnt_table_next_child_fs),
                        DLSYM_ARG(mnt_table_next_fs),
                        DLSYM_ARG(mnt_table_parse_file),
                        DLSYM_ARG(mnt_table_parse_mtab),
                        DLSYM_ARG(mnt_table_parse_stream),
                        DLSYM_ARG(mnt_table_parse_swaps),
                        DLSYM_ARG(mnt_unref_monitor));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libmount support is not compiled in.");
#endif
}
