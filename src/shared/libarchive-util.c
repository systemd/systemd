/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libarchive-util.h"

#if HAVE_LIBARCHIVE
static void *libarchive_dl = NULL;

DLSYM_PROTOTYPE(archive_entry_free) = NULL;
DLSYM_PROTOTYPE(archive_entry_new) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_ctime) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_filetype) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_gid) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_mtime) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_pathname) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_perm) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_rdevmajor) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_rdevminor) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_symlink) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_size) = NULL;
DLSYM_PROTOTYPE(archive_entry_set_uid) = NULL;
DLSYM_PROTOTYPE(archive_error_string) = NULL;
DLSYM_PROTOTYPE(archive_write_close) = NULL;
DLSYM_PROTOTYPE(archive_write_data) = NULL;
DLSYM_PROTOTYPE(archive_write_free) = NULL;
DLSYM_PROTOTYPE(archive_write_header) = NULL;
DLSYM_PROTOTYPE(archive_write_new) = NULL;
DLSYM_PROTOTYPE(archive_write_open_FILE) = NULL;
DLSYM_PROTOTYPE(archive_write_open_fd) = NULL;
DLSYM_PROTOTYPE(archive_write_set_format_filter_by_ext) = NULL;
DLSYM_PROTOTYPE(archive_write_set_format_gnutar) = NULL;

int dlopen_libarchive(void) {
        ELF_NOTE_DLOPEN("archive",
                        "Support for decompressing archive files",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libarchive.so.13");

        return dlopen_many_sym_or_warn(
                        &libarchive_dl,
                        "libarchive.so.13",
                        LOG_DEBUG,
                        DLSYM_ARG(archive_entry_free),
                        DLSYM_ARG(archive_entry_new),
                        DLSYM_ARG(archive_entry_set_ctime),
                        DLSYM_ARG(archive_entry_set_filetype),
                        DLSYM_ARG(archive_entry_set_gid),
                        DLSYM_ARG(archive_entry_set_mtime),
                        DLSYM_ARG(archive_entry_set_pathname),
                        DLSYM_ARG(archive_entry_set_perm),
                        DLSYM_ARG(archive_entry_set_rdevmajor),
                        DLSYM_ARG(archive_entry_set_rdevminor),
                        DLSYM_ARG(archive_entry_set_size),
                        DLSYM_ARG(archive_entry_set_symlink),
                        DLSYM_ARG(archive_entry_set_uid),
                        DLSYM_ARG(archive_error_string),
                        DLSYM_ARG(archive_write_close),
                        DLSYM_ARG(archive_write_data),
                        DLSYM_ARG(archive_write_free),
                        DLSYM_ARG(archive_write_header),
                        DLSYM_ARG(archive_write_new),
                        DLSYM_ARG(archive_write_open_FILE),
                        DLSYM_ARG(archive_write_open_fd),
                        DLSYM_ARG(archive_write_set_format_filter_by_ext),
                        DLSYM_ARG(archive_write_set_format_gnutar));
}

#endif
