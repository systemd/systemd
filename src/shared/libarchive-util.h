/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"

#if HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>

DLSYM_PROTOTYPE(archive_entry_free);
DLSYM_PROTOTYPE(archive_entry_new);
DLSYM_PROTOTYPE(archive_entry_set_ctime);
DLSYM_PROTOTYPE(archive_entry_set_filetype);
DLSYM_PROTOTYPE(archive_entry_set_gid);
DLSYM_PROTOTYPE(archive_entry_set_mtime);
DLSYM_PROTOTYPE(archive_entry_set_pathname);
DLSYM_PROTOTYPE(archive_entry_set_perm);
DLSYM_PROTOTYPE(archive_entry_set_rdevmajor);
DLSYM_PROTOTYPE(archive_entry_set_rdevminor);
DLSYM_PROTOTYPE(archive_entry_set_symlink);
DLSYM_PROTOTYPE(archive_entry_set_size);
DLSYM_PROTOTYPE(archive_entry_set_uid);
DLSYM_PROTOTYPE(archive_error_string);
DLSYM_PROTOTYPE(archive_write_close);
DLSYM_PROTOTYPE(archive_write_data);
DLSYM_PROTOTYPE(archive_write_free);
DLSYM_PROTOTYPE(archive_write_header);
DLSYM_PROTOTYPE(archive_write_new);
DLSYM_PROTOTYPE(archive_write_open_FILE);
DLSYM_PROTOTYPE(archive_write_open_fd);
DLSYM_PROTOTYPE(archive_write_set_format_filter_by_ext);
DLSYM_PROTOTYPE(archive_write_set_format_gnutar);

int dlopen_libarchive(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive_entry*, sym_archive_entry_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive*, sym_archive_write_free, NULL);

#else

static inline int dlopen_libarchive(void) {
        return -EOPNOTSUPP;
}

#endif
