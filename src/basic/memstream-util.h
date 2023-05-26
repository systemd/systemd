/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

typedef struct MemStream {
        FILE *f;
        char *buf;
        size_t sz;
} MemStream;

void memstream_done(MemStream *m);
int memstream_open(MemStream *m, FILE **ret);
int memstream_close(MemStream *m, char **ret_buf, size_t *ret_size);
