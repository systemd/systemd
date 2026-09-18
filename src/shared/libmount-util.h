/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlopen-note.h"
#include "forward.h"

#if HAVE_LIBMOUNT
#ifndef SYSTEMD_CFLAGS_MARKER_LIBMOUNT
#  error "missing libmount_cflags in meson dependency."
#endif

/* This needs to be after sys/mount.h */
#include <libmount.h> /* IWYU pragma: export */

#include "dlfcn-util.h"

/* The statmount()/listmount() API support is available since util-linux 2.41. Always redeclare so
 * DLSYM_PROTOTYPE's typeof() resolves on older headers; suppress the warning when newer libmount
 * already declares them. These are resolved with DLSYM_OPTIONAL, so the pointers stay NULL when the
 * runtime libmount is older, and callers fall back to parsing /proc/self/mountinfo. */
struct libmnt_statmnt;
DISABLE_WARNING_REDUNDANT_DECLS;
/* NOLINTBEGIN(readability-redundant-declaration) */
extern struct libmnt_statmnt *mnt_new_statmnt(void);
extern void mnt_unref_statmnt(struct libmnt_statmnt *sm);
extern int mnt_statmnt_set_mask(struct libmnt_statmnt *sm, uint64_t mask);
extern int mnt_table_refer_statmnt(struct libmnt_table *tb, struct libmnt_statmnt *sm);
extern int mnt_table_listmount_set_id(struct libmnt_table *tb, uint64_t id);
extern int mnt_table_fetch_listmount(struct libmnt_table *tb);
extern uint64_t mnt_fs_get_uniq_id(struct libmnt_fs *fs);
/* NOLINTEND(readability-redundant-declaration) */
REENABLE_WARNING;

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

extern DLSYM_PROTOTYPE(mnt_fs_get_uniq_id);
extern DLSYM_PROTOTYPE(mnt_new_statmnt);
extern DLSYM_PROTOTYPE(mnt_statmnt_set_mask);
extern DLSYM_PROTOTYPE(mnt_table_fetch_listmount);
extern DLSYM_PROTOTYPE(mnt_table_listmount_set_id);
extern DLSYM_PROTOTYPE(mnt_table_refer_statmnt);
extern DLSYM_PROTOTYPE(mnt_unref_statmnt);

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

/* Builds a mount table equivalent to the one libmount_parse_mountinfo() builds, but through
 * listmount()/statmount() instead of /proc/self/mountinfo, fetching only the fields the caller
 * sets in 'mask'. Equivalent is not identical: libmount does not render every field the same way
 * through the two backends. Its statmount() path spells strict atime out in the VFS options
 * string where mountinfo expresses it by omitting any atime option, and a subtyped filesystem's
 * bare type is reported here ("fuse") where mountinfo reports both ("fuse.sshfs") unless both
 * the kernel and libmount can deliver the subtype (statmount() reports it only on Linux 6.13
 * and later). A caller comparing entries against a mountinfo table must normalise those
 * fields itself. Returns -EOPNOTSUPP when the runtime libmount or the kernel lacks the syscalls,
 * and also when $SYSTEMD_LISTMOUNT=0 forces the same answer, so the caller can fall back to the
 * mountinfo parse. */
int libmount_parse_kernel(
                uint64_t mask,
                int direction,
                struct libmnt_table **ret_table,
                struct libmnt_iter **ret_iter);

int libmount_parse_fstab(struct libmnt_table **ret_table, struct libmnt_iter **ret_iter);

int libmount_is_leaf(
                struct libmnt_table *table,
                struct libmnt_fs *fs);

int libmount_fs_id_matches_path(struct libmnt_fs *fs, const char *path);

#else

struct libmnt_monitor;

static inline void* sym_mnt_unref_monitor(struct libmnt_monitor *p) {
        assert(p == NULL);
        return NULL;
}

#endif

int dlopen_libmount(int log_level) _dlopen_loader_;
