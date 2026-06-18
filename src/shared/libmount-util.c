/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libmount-util.h"
#include "log.h"

#if HAVE_LIBMOUNT

#include <stdio.h>

#include "sd-dlopen.h"

#include "fstab-util.h"

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

/* Optional listmount/statmount symbols (libmount >= 2.41) */
DLSYM_PROTOTYPE(mnt_new_statmnt) = NULL;
DLSYM_PROTOTYPE(mnt_unref_statmnt) = NULL;
DLSYM_PROTOTYPE(mnt_table_refer_statmnt) = NULL;
DLSYM_PROTOTYPE(mnt_table_fetch_listmount) = NULL;
DLSYM_PROTOTYPE(mnt_fs_get_uniq_id) = NULL;

/* Optional fanotify mount monitor symbols (libmount >= 2.42) */
DLSYM_PROTOTYPE(mnt_monitor_enable_fanotify) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_event_cleanup) = NULL;
DLSYM_PROTOTYPE(mnt_monitor_event_next_fs) = NULL;
DLSYM_PROTOTYPE(mnt_new_fs) = NULL;
DLSYM_PROTOTYPE(mnt_unref_fs) = NULL;
DLSYM_PROTOTYPE(mnt_reset_fs) = NULL;
DLSYM_PROTOTYPE(mnt_fs_refer_statmnt) = NULL;
DLSYM_PROTOTYPE(mnt_fs_fetch_statmount) = NULL;
DLSYM_PROTOTYPE(mnt_fs_is_attached) = NULL;
DLSYM_PROTOTYPE(mnt_fs_is_detached) = NULL;
DLSYM_PROTOTYPE(mnt_fs_is_moved) = NULL;

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

int libmount_fetch_listmount(
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        assert(ret_table);
        assert(ret_iter);

        r = dlopen_libmount_listmount(LOG_DEBUG);
        if (r < 0)
                return r;

        table = sym_mnt_new_table();
        if (!table)
                return -ENOMEM;

        struct libmnt_statmnt *stmnt = sym_mnt_new_statmnt();
        if (stmnt) {
                r = sym_mnt_table_refer_statmnt(table, stmnt);
                sym_mnt_unref_statmnt(stmnt);
                if (r < 0)
                        log_debug_errno(r, "Failed to set statmnt on table, ignoring: %m");
        }

        r = sym_mnt_table_fetch_listmount(table);
        if (r < 0)
                return r;

        iter = sym_mnt_new_iter(MNT_ITER_FORWARD);
        if (!iter)
                return -ENOMEM;

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

#endif

int dlopen_libmount(int log_level) {
#if HAVE_LIBMOUNT
        static void *libmount_dl = NULL;

        LIBMOUNT_NOTE(SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED);

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

int dlopen_libmount_listmount(int log_level) {
#if HAVE_LIBMOUNT
        static void *libmount_listmount_dl = NULL;
        int r;

        r = dlopen_libmount(log_level);
        if (r < 0)
                return r;

        return dlopen_many_sym_or_warn(
                        &libmount_listmount_dl,
                        "libmount.so.1",
                        log_level,
                        DLSYM_ARG(mnt_new_statmnt),
                        DLSYM_ARG(mnt_unref_statmnt),
                        DLSYM_ARG(mnt_table_refer_statmnt),
                        DLSYM_ARG(mnt_table_fetch_listmount),
                        DLSYM_ARG(mnt_fs_get_uniq_id));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libmount listmount support is not compiled in.");
#endif
}

int dlopen_libmount_fanotify(int log_level) {
#if HAVE_LIBMOUNT
        static void *libmount_fanotify_dl = NULL;
        int r;

        r = dlopen_libmount(log_level);
        if (r < 0)
                return r;

        return dlopen_many_sym_or_warn(
                        &libmount_fanotify_dl,
                        "libmount.so.1",
                        log_level,
                        DLSYM_ARG(mnt_monitor_enable_fanotify),
                        DLSYM_ARG(mnt_monitor_event_cleanup),
                        DLSYM_ARG(mnt_monitor_event_next_fs),
                        DLSYM_ARG(mnt_new_fs),
                        DLSYM_ARG(mnt_unref_fs),
                        DLSYM_ARG(mnt_reset_fs),
                        DLSYM_ARG(mnt_new_statmnt),
                        DLSYM_ARG(mnt_unref_statmnt),
                        DLSYM_ARG(mnt_fs_refer_statmnt),
                        DLSYM_ARG(mnt_fs_fetch_statmount),
                        DLSYM_ARG(mnt_fs_get_uniq_id),
                        DLSYM_ARG(mnt_fs_is_attached),
                        DLSYM_ARG(mnt_fs_is_detached),
                        DLSYM_ARG(mnt_fs_is_moved));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libmount fanotify support is not compiled in.");
#endif
}
