/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "time-util.h"

/* Make sure not to make this smaller than the maximum coredump size.
 * See COREDUMP_MAX in coredump.c */
#define ENTRY_SIZE_MAX (1024*1024*770u)
#define DATA_SIZE_MAX (1024*1024*768u)
#define LINE_CHUNK 8*1024u

struct iovec_wrapper {
        struct iovec *iovec;
        size_t size_bytes;
        size_t count;
};

size_t iovw_size(struct iovec_wrapper *iovw);

typedef struct JournalImporter {
        int fd;
        bool passive_fd;
        char *name;

        char *buf;
        size_t size;       /* total size of the buffer */
        size_t offset;     /* offset to the beginning of live data in the buffer */
        size_t scanned;    /* number of bytes since the beginning of data without a newline */
        size_t filled;     /* total number of bytes in the buffer */

        size_t field_len;  /* used for binary fields: the field name length */
        size_t data_size;  /* and the size of the binary data chunk being processed */

        struct iovec_wrapper iovw;

        int state;
        dual_timestamp ts;
} JournalImporter;

void journal_importer_cleanup(JournalImporter *);
int journal_importer_process_data(JournalImporter *);
int journal_importer_push_data(JournalImporter *, const char *data, size_t size);
void journal_importer_drop_iovw(JournalImporter *);
bool journal_importer_eof(const JournalImporter *);

static inline size_t journal_importer_bytes_remaining(const JournalImporter *imp) {
        return imp->filled;
}
