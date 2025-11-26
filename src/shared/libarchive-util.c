/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <syslog.h>

#include "libarchive-util.h"
#include "user-util.h"                  /* IWYU pragma: keep */

#if HAVE_LIBARCHIVE
static void *libarchive_dl = NULL;

DLSYM_PROTOTYPE(archive_entry_acl_add_entry) = NULL;
DLSYM_PROTOTYPE(archive_entry_acl_next) = NULL;
DLSYM_PROTOTYPE(archive_entry_acl_reset) = NULL;
DLSYM_PROTOTYPE(archive_entry_fflags) = NULL;
DLSYM_PROTOTYPE(archive_entry_filetype) = NULL;
DLSYM_PROTOTYPE(archive_entry_free) = NULL;
DLSYM_PROTOTYPE(archive_entry_gid) = NULL;
#if HAVE_ARCHIVE_ENTRY_GID_IS_SET
DLSYM_PROTOTYPE(archive_entry_gid_is_set) = NULL;
#else
int sym_archive_entry_gid_is_set(struct archive_entry *e) {
        return gid_is_valid(sym_archive_entry_gid(e));
}
#endif
DLSYM_PROTOTYPE(archive_entry_hardlink) = NULL;
#if HAVE_ARCHIVE_ENTRY_HARDLINK_IS_SET
DLSYM_PROTOTYPE(archive_entry_hardlink_is_set) = NULL;
#endif
DLSYM_PROTOTYPE(archive_entry_mode) = NULL;
DLSYM_PROTOTYPE(archive_entry_mtime) = NULL;
DLSYM_PROTOTYPE(archive_entry_mtime_is_set) = NULL;
DLSYM_PROTOTYPE(archive_entry_mtime_nsec) = NULL;
DLSYM_PROTOTYPE(archive_entry_new) = NULL;
DLSYM_PROTOTYPE(archive_entry_pathname) = NULL;
DLSYM_PROTOTYPE(archive_entry_rdevmajor) = NULL;
DLSYM_PROTOTYPE(archive_entry_rdevminor) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_ctime) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_fflags) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_filetype) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_gid) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_hardlink) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_mtime) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_pathname) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_perm) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_rdevmajor) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_rdevminor) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_size) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_symlink) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_uid) = NULL;
DLSYM_PROTOTYPE(archive_entry_sparse_add_entry) = NULL;
DLSYM_PROTOTYPE(archive_entry_symlink) = NULL;
DLSYM_PROTOTYPE(archive_entry_uid) = NULL;
#if HAVE_ARCHIVE_ENTRY_UID_IS_SET
DLSYM_PROTOTYPE(archive_entry_uid_is_set) = NULL;
#else
int sym_archive_entry_uid_is_set(struct archive_entry *e) {
        return uid_is_valid(sym_archive_entry_uid(e));
}
#endif
DLSYM_PROTOTYPE(archive_entry_xattr_add_entry) = NULL;
DLSYM_PROTOTYPE(archive_entry_xattr_next) = NULL;
DLSYM_PROTOTYPE(archive_entry_xattr_reset) = NULL;
DLSYM_PROTOTYPE(archive_error_string) = NULL;
DLSYM_PROTOTYPE(archive_read_data_into_fd) = NULL;
DLSYM_PROTOTYPE(archive_read_free) = NULL;
DLSYM_PROTOTYPE(archive_read_new) = NULL;
DLSYM_PROTOTYPE(archive_read_next_header) = NULL;
DLSYM_PROTOTYPE(archive_read_open_fd) = NULL;
DLSYM_PROTOTYPE(archive_read_support_format_cpio) = NULL;
DLSYM_PROTOTYPE(archive_read_support_format_tar) = NULL;
DLSYM_PROTOTYPE(archive_write_close) = NULL;
DLSYM_PROTOTYPE(archive_write_data) = NULL;
DLSYM_PROTOTYPE(archive_write_free) = NULL;
DLSYM_PROTOTYPE(archive_write_header) = NULL;
DLSYM_PROTOTYPE(archive_write_new) = NULL;
DLSYM_PROTOTYPE(archive_write_open_FILE) = NULL;
DLSYM_PROTOTYPE(archive_write_open_fd) = NULL;
DLSYM_PROTOTYPE(archive_write_set_format_filter_by_ext) = NULL;
DLSYM_PROTOTYPE(archive_write_set_format_pax) = NULL;

int dlopen_libarchive(void) {
        ELF_NOTE_DLOPEN("archive",
                        "Support for decompressing archive files",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libarchive.so.13");

        return dlopen_many_sym_or_warn(
                        &libarchive_dl,
                        "libarchive.so.13",
                        LOG_DEBUG,
                        DLSYM_ARG(archive_entry_acl_add_entry),
                        DLSYM_ARG(archive_entry_acl_next),
                        DLSYM_ARG(archive_entry_acl_reset),
                        DLSYM_ARG(archive_entry_fflags),
                        DLSYM_ARG(archive_entry_filetype),
                        DLSYM_ARG(archive_entry_free),
                        DLSYM_ARG(archive_entry_gid),
#if HAVE_ARCHIVE_ENTRY_GID_IS_SET
                        DLSYM_ARG(archive_entry_gid_is_set),
#endif
                        DLSYM_ARG(archive_entry_hardlink),
#if HAVE_ARCHIVE_ENTRY_HARDLINK_IS_SET
                        DLSYM_ARG(archive_entry_hardlink_is_set),
#endif
                        DLSYM_ARG(archive_entry_mode),
                        DLSYM_ARG(archive_entry_mtime),
                        DLSYM_ARG(archive_entry_mtime_is_set),
                        DLSYM_ARG(archive_entry_mtime_nsec),
                        DLSYM_ARG(archive_entry_new),
                        DLSYM_ARG(archive_entry_pathname),
                        DLSYM_ARG(archive_entry_rdevmajor),
                        DLSYM_ARG(archive_entry_rdevminor),
                        DLSYM_ARG(archive_entry_set_ctime),
                        DLSYM_ARG(archive_entry_set_fflags),
                        DLSYM_ARG(archive_entry_set_filetype),
                        DLSYM_ARG(archive_entry_set_gid),
                        DLSYM_ARG(archive_entry_set_hardlink),
                        DLSYM_ARG(archive_entry_set_mtime),
                        DLSYM_ARG(archive_entry_set_pathname),
                        DLSYM_ARG(archive_entry_set_perm),
                        DLSYM_ARG(archive_entry_set_rdevmajor),
                        DLSYM_ARG(archive_entry_set_rdevminor),
                        DLSYM_ARG(archive_entry_set_size),
                        DLSYM_ARG(archive_entry_set_symlink),
                        DLSYM_ARG(archive_entry_set_uid),
                        DLSYM_ARG(archive_entry_sparse_add_entry),
                        DLSYM_ARG(archive_entry_symlink),
                        DLSYM_ARG(archive_entry_uid),
#if HAVE_ARCHIVE_ENTRY_UID_IS_SET
                        DLSYM_ARG(archive_entry_uid_is_set),
#endif
                        DLSYM_ARG(archive_entry_xattr_add_entry),
                        DLSYM_ARG(archive_entry_xattr_next),
                        DLSYM_ARG(archive_entry_xattr_reset),
                        DLSYM_ARG(archive_error_string),
                        DLSYM_ARG(archive_read_data_into_fd),
                        DLSYM_ARG(archive_read_free),
                        DLSYM_ARG(archive_read_new),
                        DLSYM_ARG(archive_read_next_header),
                        DLSYM_ARG(archive_read_open_fd),
                        DLSYM_ARG(archive_read_support_format_cpio),
                        DLSYM_ARG(archive_read_support_format_tar),
                        DLSYM_ARG(archive_write_close),
                        DLSYM_ARG(archive_write_data),
                        DLSYM_ARG(archive_write_free),
                        DLSYM_ARG(archive_write_header),
                        DLSYM_ARG(archive_write_new),
                        DLSYM_ARG(archive_write_open_FILE),
                        DLSYM_ARG(archive_write_open_fd),
                        DLSYM_ARG(archive_write_set_format_filter_by_ext),
                        DLSYM_ARG(archive_write_set_format_pax));
}

/* libarchive uses its own file type macros. They happen to be defined the same way as the Linux ones, and
 * we'd like to rely on it. Let's verify this first though. */
assert_cc(S_IFDIR == AE_IFDIR);
assert_cc(S_IFREG == AE_IFREG);
assert_cc(S_IFLNK == AE_IFLNK);
assert_cc(S_IFBLK == AE_IFBLK);
assert_cc(S_IFCHR == AE_IFCHR);
assert_cc(S_IFIFO == AE_IFIFO);
assert_cc(S_IFSOCK == AE_IFSOCK);

#endif
