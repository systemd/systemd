/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "sd-id128.h"

#include "shared-forward.h"
#include "iovec-wrapper.h"
#include "time-util.h"

/* Make sure not to make this smaller than the maximum coredump size.
 * See JOURNAL_SIZE_MAX in coredump.c */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define ENTRY_SIZE_MAX (1024*1024*770u)
#define ENTRY_SIZE_UNPRIV_MAX (1024*1024*32u)
#define DATA_SIZE_MAX (1024*1024*768u)
#else
#define ENTRY_SIZE_MAX (1024*1024*13u)
#define ENTRY_SIZE_UNPRIV_MAX (1024*1024*8u)
#define DATA_SIZE_MAX (1024*1024*11u)
#endif
#define LINE_CHUNK 8*1024u

/* The maximum number of fields in an entry */
#define ENTRY_FIELD_COUNT_MAX 1024u

typedef struct JournalImporter {
        int fd;
        bool passive_fd;
        char *name;

        char *buf;
        size_t offset;     /* offset to the beginning of live data in the buffer */
        size_t scanned;    /* number of bytes since the beginning of data without a newline */
        size_t filled;     /* total number of bytes in the buffer */

        size_t field_len;  /* used for binary fields: the field name length */
        size_t data_size;  /* and the size of the binary data chunk being processed */

        struct iovec_wrapper iovw;

        int state;
        dual_timestamp ts;
        sd_id128_t boot_id;
} JournalImporter;

#define JOURNAL_IMPORTER_INIT(_fd) { .fd = (_fd), .iovw = {} }
#define JOURNAL_IMPORTER_MAKE(_fd) (JournalImporter) JOURNAL_IMPORTER_INIT(_fd)

void journal_importer_cleanup(JournalImporter *imp);
int journal_importer_process_data(JournalImporter *imp);
int journal_importer_push_data(JournalImporter *imp, const char *data, size_t size);
void journal_importer_drop_iovw(JournalImporter *imp);
bool journal_importer_eof(const JournalImporter *imp);

static inline size_t journal_importer_bytes_remaining(const JournalImporter *imp) {
        return imp->filled;
}
