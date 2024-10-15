/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Copyright © 2019 Oracle and/or its affiliates. */

/* Generally speaking, the pstore contains a small number of files
 * that in turn contain a small amount of data.  */
#include <errno.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-journal.h"
#include "sd-login.h"
#include "sd-messages.h"

#include "acl-util.h"
#include "alloc-util.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "compress.h"
#include "conf-parser.h"
#include "copy.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "journal-importer.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "mkdir.h"
#include "parse-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "special.h"
#include "sort-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

/* Command line argument handling */
typedef enum PStoreStorage {
        PSTORE_STORAGE_NONE,
        PSTORE_STORAGE_EXTERNAL,
        PSTORE_STORAGE_JOURNAL,
        _PSTORE_STORAGE_MAX,
        _PSTORE_STORAGE_INVALID = -EINVAL,
} PStoreStorage;

static const char* const pstore_storage_table[_PSTORE_STORAGE_MAX] = {
        [PSTORE_STORAGE_NONE]     = "none",
        [PSTORE_STORAGE_EXTERNAL] = "external",
        [PSTORE_STORAGE_JOURNAL]  = "journal",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(pstore_storage, PStoreStorage);
static DEFINE_CONFIG_PARSE_ENUM(config_parse_pstore_storage, pstore_storage, PStoreStorage);

static PStoreStorage arg_storage = PSTORE_STORAGE_EXTERNAL;

static bool arg_unlink = true;
static const char *arg_sourcedir = "/sys/fs/pstore";
static const char *arg_archivedir = "/var/lib/systemd/pstore";

static int parse_config(void) {
        static const ConfigTableItem items[] = {
                { "PStore", "Unlink",  config_parse_bool,           0, &arg_unlink },
                { "PStore", "Storage", config_parse_pstore_storage, 0, &arg_storage },
                {}
        };

        return config_parse_standard_file_with_dropins(
                        "systemd/pstore.conf",
                        "PStore\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
}

/* File list handling - PStoreEntry is the struct and
 * and PStoreEntry is the type that contains all info
 * about a pstore entry.  */
typedef struct PStoreEntry {
        struct dirent dirent;
        bool is_binary;
        bool handled;
        char *content;
        size_t content_size;
} PStoreEntry;

typedef struct PStoreList {
        PStoreEntry *entries;
        size_t n_entries;
} PStoreList;

static void pstore_entries_reset(PStoreList *list) {
        for (size_t i = 0; i < list->n_entries; i++)
                free(list->entries[i].content);
        free(list->entries);
        list->n_entries = 0;
}

static int compare_pstore_entries(const PStoreEntry *a, const PStoreEntry *b) {
        return strcmp(a->dirent.d_name, b->dirent.d_name);
}

static int move_file(PStoreEntry *pe, const char *subdir1, const char *subdir2) {
        _cleanup_free_ char *ifd_path = NULL, *ofd_path = NULL;
        _cleanup_free_ void *field = NULL;
        const char *suffix, *message;
        struct iovec iovec[2];
        int n_iovec = 0, r;

        if (pe->handled)
                return 0;

        ifd_path = path_join(arg_sourcedir, pe->dirent.d_name);
        if (!ifd_path)
                return log_oom();

        ofd_path = path_join(arg_archivedir, subdir1, subdir2, pe->dirent.d_name);
        if (!ofd_path)
                return log_oom();

        /* Always log to the journal */
        suffix = arg_storage == PSTORE_STORAGE_EXTERNAL ? strjoina(" moved to ", ofd_path) : (char *)".";
        message = strjoina("MESSAGE=PStore ", pe->dirent.d_name, suffix);
        iovec[n_iovec++] = IOVEC_MAKE_STRING(message);

        if (pe->content_size > 0) {
                size_t field_size;

                field_size = strlen("FILE=") + pe->content_size;
                field = malloc(field_size);
                if (!field)
                        return log_oom();
                memcpy(stpcpy(field, "FILE="), pe->content, pe->content_size);
                iovec[n_iovec++] = IOVEC_MAKE(field, field_size);
        }

        r = sd_journal_sendv(iovec, n_iovec);
        if (r < 0)
                return log_error_errno(r, "Failed to log pstore entry: %m");

        if (arg_storage == PSTORE_STORAGE_EXTERNAL) {
                /* Move file from pstore to external storage */
                r = mkdir_parents(ofd_path, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory %s: %m", ofd_path);
                r = copy_file_atomic(ifd_path, ofd_path, 0600, COPY_REPLACE);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy_file_atomic: %s to %s", ifd_path, ofd_path);
        }

        /* If file copied properly, remove it from pstore */
        if (arg_unlink)
                (void) unlink(ifd_path);

        pe->handled = true;

        return 0;
}

static int append_dmesg(PStoreEntry *pe, const char *subdir1, const char *subdir2) {
        /* Append dmesg chunk to end, create if needed */
        _cleanup_free_ char *ofd_path = NULL;
        _cleanup_close_ int ofd = -EBADF;
        ssize_t wr;

        assert(pe);

        if (arg_storage != PSTORE_STORAGE_EXTERNAL)
                return 0;

        if (pe->content_size == 0)
                return 0;

        ofd_path = path_join(arg_archivedir, subdir1, subdir2, "dmesg.txt");
        if (!ofd_path)
                return log_oom();

        ofd = open(ofd_path, O_CREAT|O_NOFOLLOW|O_NOCTTY|O_CLOEXEC|O_APPEND|O_WRONLY, 0640);
        if (ofd < 0)
                return log_error_errno(ofd, "Failed to open file %s: %m", ofd_path);
        wr = write(ofd, pe->content, pe->content_size);
        if (wr < 0)
                return log_error_errno(errno, "Failed to store dmesg to %s: %m", ofd_path);
        if ((size_t)wr != pe->content_size)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to store dmesg to %s. %zu bytes are lost.", ofd_path, pe->content_size - wr);

        return 0;
}

static int process_dmesg_files(PStoreList *list) {
        /* Move files, reconstruct dmesg.txt */
        _cleanup_free_ char *erst_subdir = NULL;
        unsigned long long last_record_id = 0;

        /* When dmesg is written into pstore, it is done so in small chunks, whatever the exchange buffer
         * size is with the underlying pstore backend (ie. EFI may be ~2KiB), which means an example
         * pstore with approximately 64KB of storage may have up to roughly 32 dmesg files, some likely
         * related.
         *
         * Here we look at the dmesg filename and try to discern if files are part of a related group,
         * meaning the same original dmesg.
         *
         * The dmesg- filename contains the backend-type and the Common Platform Error Record, CPER,
         * record id, a 64-bit number.
         *
         * Files are processed in reverse lexigraphical order so as to properly reconstruct original dmesg. */

        for (size_t n = list->n_entries; n > 0; n--) {
                PStoreEntry *pe;
                char *p;

                pe = &list->entries[n-1];

                if (pe->handled)
                        continue;
                if (endswith(pe->dirent.d_name, ".enc.z")) /* indicates a problem */
                        continue;
                if (!startswith(pe->dirent.d_name, "dmesg-"))
                        continue;

                /* The linux kernel changed the prefix from dmesg-efi- to dmesg-efi_pstore-
                 * so now we have to handle both cases. */
                if ((p = STARTSWITH_SET(pe->dirent.d_name, "dmesg-efi-", "dmesg-efi_pstore-"))) {
                        /* For the EFI backend, the 3 least significant digits of record id encodes a
                         * "count" number, the next 2 least significant digits for the dmesg part
                         * (chunk) number, and the remaining digits as the timestamp.  See
                         * linux/drivers/firmware/efi/efi-pstore.c in efi_pstore_write(). */
                        _cleanup_free_ char *subdir1 = NULL, *subdir2 = NULL;
                        size_t plen = strlen(p);

                        if (plen < 6)
                                continue;

                        /* Extract base record id */
                        subdir1 = strndup(p, plen - 5);
                        if (!subdir1)
                                return log_oom();
                        /* Extract "count" field */
                        subdir2 = strndup(p + plen - 3, 3);
                        if (!subdir2)
                                return log_oom();

                        /* Now move file from pstore to archive storage */
                        (void) move_file(pe, subdir1, subdir2);

                        /* Append to the dmesg */
                        (void) append_dmesg(pe, subdir1, subdir2);
                } else if ((p = startswith(pe->dirent.d_name, "dmesg-erst-"))) {
                        /* For the ERST backend, the record is a monotonically increasing number, seeded as
                         * a timestamp. See linux/drivers/acpi/apei/erst.c in erst_writer(). */
                        unsigned long long record_id;

                        if (safe_atollu_full(p, 10, &record_id) < 0)
                                continue;
                        if (last_record_id - 1 != record_id)
                                /* A discontinuity in the number has been detected, this current record id
                                 * will become the directory name for all pieces of the dmesg in this
                                 * series. */
                                if (free_and_strdup(&erst_subdir, p) < 0)
                                        return log_oom();

                        /* Now move file from pstore to archive storage */
                        (void) move_file(pe, erst_subdir, NULL);

                        /* Append to the dmesg */
                        (void) append_dmesg(pe, erst_subdir, NULL);

                        /* Update, but keep erst_subdir for next file */
                        last_record_id = record_id;
                } else
                        log_debug("Unknown backend, ignoring \"%s\".", pe->dirent.d_name);
        }

        return 0;
}

static int list_files(PStoreList *list, const char *sourcepath) {
        _cleanup_closedir_ DIR *dirp = NULL;
        int r;

        dirp = opendir(sourcepath);
        if (!dirp)
                return log_error_errno(errno, "Failed to opendir %s: %m", sourcepath);

        FOREACH_DIRENT(de, dirp, return log_error_errno(errno, "Failed to iterate through %s: %m", sourcepath)) {
                _cleanup_free_ char *ifd_path = NULL;

                ifd_path = path_join(sourcepath, de->d_name);
                if (!ifd_path)
                        return log_oom();

                _cleanup_free_ char *buf = NULL;
                size_t buf_size;

                /* Now read contents of pstore file */
                r = read_full_virtual_file(ifd_path, &buf, &buf_size);
                if (r < 0) {
                        log_warning_errno(r, "Failed to read file %s, skipping: %m", ifd_path);
                        continue;
                }

                if (!GREEDY_REALLOC(list->entries, list->n_entries + 1))
                        return log_oom();

                list->entries[list->n_entries++] = (PStoreEntry) {
                        .dirent = *de,
                        .content = TAKE_PTR(buf),
                        .content_size = buf_size,
                        .is_binary = true,
                        .handled = false,
                };
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(pstore_entries_reset) PStoreList list = {};
        int r;

        log_setup();

        if (argc == 3) {
                arg_sourcedir = argv[1];
                arg_archivedir = argv[2];
        } else if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes zero or two arguments.");

        /* Ignore all parse errors */
        (void) parse_config();

        log_debug("Selected storage: %s.", pstore_storage_to_string(arg_storage));
        log_debug("Selected unlink: %s.", yes_no(arg_unlink));

        if (arg_storage == PSTORE_STORAGE_NONE)
                /* Do nothing, intentionally, leaving pstore untouched */
                return 0;

        /* Obtain list of files in pstore */
        r = list_files(&list, arg_sourcedir);
        if (r < 0)
                return r;

        /* Handle each pstore file */
        /* Sort files lexicographically ascending, generally needed by all */
        typesafe_qsort(list.entries, list.n_entries, compare_pstore_entries);

        /* Process known file types */
        (void) process_dmesg_files(&list);

        /* Move left over files out of pstore */
        for (size_t n = 0; n < list.n_entries; n++)
                (void) move_file(&list.entries[n], NULL, NULL);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
