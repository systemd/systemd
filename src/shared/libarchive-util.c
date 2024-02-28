/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libarchive-util.h"

#if HAVE_LIBARCHIVE
static void *libarchive_dl = NULL;

DLSYM_FUNCTION(archive_entry_free);
DLSYM_FUNCTION(archive_entry_new);
DLSYM_FUNCTION(archive_entry_set_ctime);
DLSYM_FUNCTION(archive_entry_set_filetype);
DLSYM_FUNCTION(archive_entry_set_gid);
DLSYM_FUNCTION(archive_entry_set_mtime);
DLSYM_FUNCTION(archive_entry_set_pathname);
DLSYM_FUNCTION(archive_entry_set_perm);
DLSYM_FUNCTION(archive_entry_set_rdevmajor);
DLSYM_FUNCTION(archive_entry_set_rdevminor);
DLSYM_FUNCTION(archive_entry_set_symlink);
DLSYM_FUNCTION(archive_entry_set_size);
DLSYM_FUNCTION(archive_entry_set_uid);
DLSYM_FUNCTION(archive_error_string);
DLSYM_FUNCTION(archive_write_close);
DLSYM_FUNCTION(archive_write_data);
DLSYM_FUNCTION(archive_write_free);
DLSYM_FUNCTION(archive_write_header);
DLSYM_FUNCTION(archive_write_new);
DLSYM_FUNCTION(archive_write_open_FILE);
DLSYM_FUNCTION(archive_write_open_fd);
DLSYM_FUNCTION(archive_write_set_format_filter_by_ext);
DLSYM_FUNCTION(archive_write_set_format_gnutar);

int dlopen_libarchive(void) {
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
