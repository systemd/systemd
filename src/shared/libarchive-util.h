/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#if HAVE_LIBARCHIVE
#include <archive.h>            /* IWYU pragma: export */
#include <archive_entry.h>      /* IWYU pragma: export */

#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(archive_entry_filetype);
extern DLSYM_PROTOTYPE(archive_entry_free);
extern DLSYM_PROTOTYPE(archive_entry_gid);
extern DLSYM_PROTOTYPE(archive_entry_hardlink);
extern DLSYM_PROTOTYPE(archive_entry_mode);
extern DLSYM_PROTOTYPE(archive_entry_mtime);
extern DLSYM_PROTOTYPE(archive_entry_mtime_is_set);
extern DLSYM_PROTOTYPE(archive_entry_mtime_nsec);
extern DLSYM_PROTOTYPE(archive_entry_new);
extern DLSYM_PROTOTYPE(archive_entry_pathname);
extern DLSYM_PROTOTYPE(archive_entry_rdevmajor);
extern DLSYM_PROTOTYPE(archive_entry_rdevminor);
extern DLSYM_PROTOTYPE(archive_entry_set_ctime);
extern DLSYM_PROTOTYPE(archive_entry_set_filetype);
extern DLSYM_PROTOTYPE(archive_entry_set_gid);
extern DLSYM_PROTOTYPE(archive_entry_set_mtime);
extern DLSYM_PROTOTYPE(archive_entry_set_pathname);
extern DLSYM_PROTOTYPE(archive_entry_set_perm);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevmajor);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevminor);
extern DLSYM_PROTOTYPE(archive_entry_set_size);
extern DLSYM_PROTOTYPE(archive_entry_set_symlink);
extern DLSYM_PROTOTYPE(archive_entry_set_uid);
extern DLSYM_PROTOTYPE(archive_entry_symlink);
extern DLSYM_PROTOTYPE(archive_entry_uid);
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
extern DLSYM_PROTOTYPE(archive_write_set_format_gnutar);

#if HAVE_LIBARCHIVE_UID_IS_SET
extern DLSYM_PROTOTYPE(archive_entry_gid_is_set);
extern DLSYM_PROTOTYPE(archive_entry_uid_is_set);
#else
#include "user-util.h"
static inline int sym_archive_entry_gid_is_set(struct archive_entry *e) {
        return gid_is_valid(sym_archive_entry_gid(e));
}
static inline int sym_archive_entry_uid_is_set(struct archive_entry *e) {
        return uid_is_valid(sym_archive_entry_uid(e));
}
#endif

#if HAVE_LIBARCHIVE_HARDLINK_IS_SET
extern DLSYM_PROTOTYPE(archive_entry_hardlink_is_set);
#else
static inline int sym_archive_entry_hardlink_is_set(struct archive_entry *e) {
        return !!sym_archive_entry_hardlink(e);
}
#endif

int dlopen_libarchive(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive_entry*, sym_archive_entry_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive*, sym_archive_write_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive*, sym_archive_read_free, NULL);

#else

static inline int dlopen_libarchive(void) {
        return -EOPNOTSUPP;
}

#endif
