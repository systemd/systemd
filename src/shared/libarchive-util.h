/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBARCHIVE
#include <archive.h>            /* IWYU pragma: export */
#include <archive_entry.h>      /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(archive_entry_acl_add_entry);
extern DLSYM_PROTOTYPE(archive_entry_acl_next);
extern DLSYM_PROTOTYPE(archive_entry_acl_reset);
extern DLSYM_PROTOTYPE(archive_entry_fflags);
extern DLSYM_PROTOTYPE(archive_entry_filetype);
extern DLSYM_PROTOTYPE(archive_entry_free);
extern DLSYM_PROTOTYPE(archive_entry_gid);
#if HAVE_ARCHIVE_ENTRY_GID_IS_SET
extern DLSYM_PROTOTYPE(archive_entry_gid_is_set);
#else
int sym_archive_entry_gid_is_set(struct archive_entry *e);
#endif
extern DLSYM_PROTOTYPE(archive_entry_hardlink);
#if HAVE_ARCHIVE_ENTRY_HARDLINK_IS_SET
extern DLSYM_PROTOTYPE(archive_entry_hardlink_is_set);
#else
static inline int sym_archive_entry_hardlink_is_set(struct archive_entry *e) {
        return !!sym_archive_entry_hardlink(e);
}
#endif
extern DLSYM_PROTOTYPE(archive_entry_mode);
extern DLSYM_PROTOTYPE(archive_entry_mtime);
extern DLSYM_PROTOTYPE(archive_entry_mtime_is_set);
extern DLSYM_PROTOTYPE(archive_entry_mtime_nsec);
extern DLSYM_PROTOTYPE(archive_entry_new);
extern DLSYM_PROTOTYPE(archive_entry_pathname);
extern DLSYM_PROTOTYPE(archive_entry_rdevmajor);
extern DLSYM_PROTOTYPE(archive_entry_rdevminor);
extern DLSYM_PROTOTYPE(archive_entry_set_ctime);
extern DLSYM_PROTOTYPE(archive_entry_set_fflags);
extern DLSYM_PROTOTYPE(archive_entry_set_filetype);
extern DLSYM_PROTOTYPE(archive_entry_set_gid);
extern DLSYM_PROTOTYPE(archive_entry_set_hardlink);
extern DLSYM_PROTOTYPE(archive_entry_set_mtime);
extern DLSYM_PROTOTYPE(archive_entry_set_pathname);
extern DLSYM_PROTOTYPE(archive_entry_set_perm);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevmajor);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevminor);
extern DLSYM_PROTOTYPE(archive_entry_set_size);
extern DLSYM_PROTOTYPE(archive_entry_set_symlink);
extern DLSYM_PROTOTYPE(archive_entry_set_uid);
extern DLSYM_PROTOTYPE(archive_entry_sparse_add_entry);
extern DLSYM_PROTOTYPE(archive_entry_symlink);
extern DLSYM_PROTOTYPE(archive_entry_uid);
#if HAVE_ARCHIVE_ENTRY_UID_IS_SET
extern DLSYM_PROTOTYPE(archive_entry_uid_is_set);
#else
int sym_archive_entry_uid_is_set(struct archive_entry *e);
#endif
extern DLSYM_PROTOTYPE(archive_entry_xattr_add_entry);
extern DLSYM_PROTOTYPE(archive_entry_xattr_next);
extern DLSYM_PROTOTYPE(archive_entry_xattr_reset);
extern DLSYM_PROTOTYPE(archive_error_string);
extern DLSYM_PROTOTYPE(archive_read_data_into_fd);
extern DLSYM_PROTOTYPE(archive_read_free);
extern DLSYM_PROTOTYPE(archive_read_new);
extern DLSYM_PROTOTYPE(archive_read_next_header);
extern DLSYM_PROTOTYPE(archive_read_open_fd);
extern DLSYM_PROTOTYPE(archive_read_support_format_cpio);
extern DLSYM_PROTOTYPE(archive_read_support_format_tar);
extern DLSYM_PROTOTYPE(archive_write_close);
extern DLSYM_PROTOTYPE(archive_write_data);
extern DLSYM_PROTOTYPE(archive_write_free);
extern DLSYM_PROTOTYPE(archive_write_header);
extern DLSYM_PROTOTYPE(archive_write_new);
extern DLSYM_PROTOTYPE(archive_write_open_FILE);
extern DLSYM_PROTOTYPE(archive_write_open_fd);
extern DLSYM_PROTOTYPE(archive_write_set_format_filter_by_ext);
extern DLSYM_PROTOTYPE(archive_write_set_format_pax);

int dlopen_libarchive(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct archive_entry*, sym_archive_entry_free, archive_entry_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct archive*, sym_archive_write_free, archive_write_freep, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(struct archive*, sym_archive_read_free, archive_read_freep, NULL);

#else

static inline int dlopen_libarchive(void) {
        return -EOPNOTSUPP;
}

#endif
