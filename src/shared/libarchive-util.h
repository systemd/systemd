/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"

#if HAVE_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>

extern DLSYM_PROTOTYPE(archive_entry_free);
extern DLSYM_PROTOTYPE(archive_entry_new);
extern DLSYM_PROTOTYPE(archive_entry_set_ctime);
extern DLSYM_PROTOTYPE(archive_entry_set_filetype);
extern DLSYM_PROTOTYPE(archive_entry_set_gid);
extern DLSYM_PROTOTYPE(archive_entry_set_mtime);
extern DLSYM_PROTOTYPE(archive_entry_set_pathname);
extern DLSYM_PROTOTYPE(archive_entry_set_perm);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevmajor);
extern DLSYM_PROTOTYPE(archive_entry_set_rdevminor);
extern DLSYM_PROTOTYPE(archive_entry_set_symlink);
extern DLSYM_PROTOTYPE(archive_entry_set_size);
extern DLSYM_PROTOTYPE(archive_entry_set_uid);
extern DLSYM_PROTOTYPE(archive_error_string);
extern DLSYM_PROTOTYPE(archive_write_close);
extern DLSYM_PROTOTYPE(archive_write_data);
extern DLSYM_PROTOTYPE(archive_write_free);
extern DLSYM_PROTOTYPE(archive_write_header);
extern DLSYM_PROTOTYPE(archive_write_new);
extern DLSYM_PROTOTYPE(archive_write_open_FILE);
extern DLSYM_PROTOTYPE(archive_write_open_fd);
extern DLSYM_PROTOTYPE(archive_write_set_format_filter_by_ext);
extern DLSYM_PROTOTYPE(archive_write_set_format_gnutar);

int dlopen_libarchive(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive_entry*, sym_archive_entry_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct archive*, sym_archive_write_free, NULL);

#else

static inline int dlopen_libarchive(void) {
        return -EOPNOTSUPP;
}

#endif
