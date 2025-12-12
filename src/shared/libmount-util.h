/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBMOUNT

/* This needs to be after sys/mount.h */
#include <libmount.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(mnt_free_iter);
extern DLSYM_PROTOTYPE(mnt_free_table);
extern DLSYM_PROTOTYPE(mnt_fs_get_fs_options);
extern DLSYM_PROTOTYPE(mnt_fs_get_fstype);
extern DLSYM_PROTOTYPE(mnt_fs_get_id);
extern DLSYM_PROTOTYPE(mnt_fs_get_option);
extern DLSYM_PROTOTYPE(mnt_fs_get_options);
extern DLSYM_PROTOTYPE(mnt_fs_get_passno);
extern DLSYM_PROTOTYPE(mnt_fs_get_propagation);
extern DLSYM_PROTOTYPE(mnt_fs_get_source);
extern DLSYM_PROTOTYPE(mnt_fs_get_target);
extern DLSYM_PROTOTYPE(mnt_fs_get_vfs_options);
extern DLSYM_PROTOTYPE(mnt_get_builtin_optmap);
extern DLSYM_PROTOTYPE(mnt_init_debug);
extern DLSYM_PROTOTYPE(mnt_monitor_enable_kernel);
extern DLSYM_PROTOTYPE(mnt_monitor_enable_userspace);
extern DLSYM_PROTOTYPE(mnt_monitor_get_fd);
extern DLSYM_PROTOTYPE(mnt_monitor_next_change);
extern DLSYM_PROTOTYPE(mnt_new_iter);
extern DLSYM_PROTOTYPE(mnt_new_monitor);
extern DLSYM_PROTOTYPE(mnt_new_table);
extern DLSYM_PROTOTYPE(mnt_optstr_get_flags);
extern DLSYM_PROTOTYPE(mnt_table_find_devno);
extern DLSYM_PROTOTYPE(mnt_table_find_target);
extern DLSYM_PROTOTYPE(mnt_table_next_child_fs);
extern DLSYM_PROTOTYPE(mnt_table_next_fs);
extern DLSYM_PROTOTYPE(mnt_table_parse_file);
extern DLSYM_PROTOTYPE(mnt_table_parse_mtab);
extern DLSYM_PROTOTYPE(mnt_table_parse_stream);
extern DLSYM_PROTOTYPE(mnt_table_parse_swaps);
extern DLSYM_PROTOTYPE(mnt_unref_monitor);

int dlopen_libmount(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_table*, sym_mnt_free_table, mnt_free_tablep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_iter*, sym_mnt_free_iter, mnt_free_iterp, NULL);

int libmount_parse_full(
                const char *path,
                FILE *source,
                int direction,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter);

static inline int libmount_parse_mountinfo(
                FILE *source,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter) {

        return libmount_parse_full("/proc/self/mountinfo", source, MNT_ITER_FORWARD, ret_table, ret_iter);
}

static inline int libmount_parse_with_utab(
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter) {

        return libmount_parse_full(NULL, NULL, MNT_ITER_FORWARD, ret_table, ret_iter);
}

int libmount_parse_fstab(struct libmnt_table **ret_table, struct libmnt_iter **ret_iter);

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs);

#else

struct libmnt_monitor;

static inline int dlopen_libmount(void) {
        return -EOPNOTSUPP;
}

static inline void* sym_mnt_unref_monitor(struct libmnt_monitor *p) {
        assert(p == NULL);
        return NULL;
}

#endif
