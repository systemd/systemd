/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-dlopen.h"

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
extern DLSYM_PROTOTYPE(mnt_fs_get_user_options);
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

/* Available since libmount 2.41. Always redeclare so DLSYM_PROTOTYPE's typeof() resolves on older
 * headers; suppress the warning when newer libmount already declares them. */
struct libmnt_statmnt;
DISABLE_WARNING_REDUNDANT_DECLS;
extern struct libmnt_statmnt *mnt_new_statmnt(void);
extern void mnt_unref_statmnt(struct libmnt_statmnt *sm);
extern int mnt_table_refer_statmnt(struct libmnt_table *tb, struct libmnt_statmnt *sm);
extern int mnt_table_fetch_listmount(struct libmnt_table *tb);
extern uint64_t mnt_fs_get_uniq_id(struct libmnt_fs *fs);

/* Available since libmount 2.42 (fanotify mount monitoring). */
extern int mnt_monitor_enable_fanotify(struct libmnt_monitor *mn, int enable, int ns);
extern int mnt_monitor_event_cleanup(struct libmnt_monitor *mn);
extern int mnt_monitor_event_next_fs(struct libmnt_monitor *mn, struct libmnt_fs *fs);
extern struct libmnt_fs *mnt_new_fs(void);
extern void mnt_unref_fs(struct libmnt_fs *fs);
extern void mnt_reset_fs(struct libmnt_fs *fs);
extern int mnt_fs_refer_statmnt(struct libmnt_fs *fs, struct libmnt_statmnt *sm);
extern int mnt_fs_fetch_statmount(struct libmnt_fs *fs, uint64_t mask);
extern int mnt_fs_is_attached(struct libmnt_fs *fs);
extern int mnt_fs_is_detached(struct libmnt_fs *fs);
extern int mnt_fs_is_moved(struct libmnt_fs *fs);
REENABLE_WARNING;

#ifndef MNT_MONITOR_TYPE_FANOTIFY
#define MNT_MONITOR_TYPE_FANOTIFY 3
#endif

extern DLSYM_PROTOTYPE(mnt_new_statmnt);
extern DLSYM_PROTOTYPE(mnt_unref_statmnt);
extern DLSYM_PROTOTYPE(mnt_table_refer_statmnt);
extern DLSYM_PROTOTYPE(mnt_table_fetch_listmount);
extern DLSYM_PROTOTYPE(mnt_fs_get_uniq_id);

extern DLSYM_PROTOTYPE(mnt_monitor_enable_fanotify);
extern DLSYM_PROTOTYPE(mnt_monitor_event_cleanup);
extern DLSYM_PROTOTYPE(mnt_monitor_event_next_fs);
extern DLSYM_PROTOTYPE(mnt_new_fs);
extern DLSYM_PROTOTYPE(mnt_unref_fs);
extern DLSYM_PROTOTYPE(mnt_reset_fs);
extern DLSYM_PROTOTYPE(mnt_fs_refer_statmnt);
extern DLSYM_PROTOTYPE(mnt_fs_fetch_statmount);
extern DLSYM_PROTOTYPE(mnt_fs_is_attached);
extern DLSYM_PROTOTYPE(mnt_fs_is_detached);
extern DLSYM_PROTOTYPE(mnt_fs_is_moved);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_table*, sym_mnt_free_table, mnt_free_tablep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_iter*, sym_mnt_free_iter, mnt_free_iterp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_statmnt*, sym_mnt_unref_statmnt, mnt_unref_statmntp, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct libmnt_monitor*, sym_mnt_unref_monitor, mnt_unref_monitorp, NULL);

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

int libmount_fetch_listmount(struct libmnt_table **ret_table, struct libmnt_iter **ret_iter);

int libmount_parse_fstab(struct libmnt_table **ret_table, struct libmnt_iter **ret_iter);

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs);

#define LIBMOUNT_NOTE(priority)                                         \
        SD_ELF_NOTE_DLOPEN("mount",                                     \
                           "Support for mount enumeration",             \
                           priority,                                    \
                           "libmount.so.1")

#define DLOPEN_LIBMOUNT(log_level, priority)                            \
        ({                                                              \
                LIBMOUNT_NOTE(priority);                                \
                dlopen_libmount(log_level);                             \
        })

#define DLOPEN_LIBMOUNT_LISTMOUNT(log_level, priority)                  \
        ({                                                              \
                LIBMOUNT_NOTE(priority);                                \
                dlopen_libmount_listmount(log_level);                   \
        })

#define DLOPEN_LIBMOUNT_FANOTIFY(log_level, priority)                   \
        ({                                                              \
                LIBMOUNT_NOTE(priority);                                \
                dlopen_libmount_fanotify(log_level);                    \
        })
#else

struct libmnt_monitor;


static inline void* sym_mnt_unref_monitor(struct libmnt_monitor *p) {
        assert(p == NULL);
        return NULL;
}

#define DLOPEN_LIBMOUNT(log_level, priority) dlopen_libmount(log_level)
#define DLOPEN_LIBMOUNT_LISTMOUNT(log_level, priority) dlopen_libmount_listmount(log_level)
#define DLOPEN_LIBMOUNT_FANOTIFY(log_level, priority) dlopen_libmount_fanotify(log_level)
#endif

int dlopen_libmount(int log_level);
int dlopen_libmount_listmount(int log_level);
int dlopen_libmount_fanotify(int log_level);
