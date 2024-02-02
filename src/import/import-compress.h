/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_BZIP2
#include <bzlib.h>
#endif
#include <lzma.h>
#include <sys/types.h>
#include <zlib.h>
#include <zstd.h>

#include "macro.h"
#include "import-util.h"

typedef struct ImportCompress {
        ImportCompressType type;
        bool encoding;
        union {
                lzma_stream xz;
                z_stream gzip;
#if HAVE_BZIP2
                bz_stream bzip2;
#endif
                ZSTD_DStream *zstd_d;
                ZSTD_CStream *zstd_c;
        };
} ImportCompress;

typedef int (*ImportCompressCallback)(const void *data, size_t size, void *userdata);

void import_compress_free(ImportCompress *c);

int import_uncompress_detect(ImportCompress *c, const void *data, size_t size);
void import_uncompress_force_off(ImportCompress *c);
int import_uncompress(ImportCompress *c, const void *data, size_t size, ImportCompressCallback callback, void *userdata);

int import_compress_init(ImportCompress *c, ImportCompressType t);
int import_compress(ImportCompress *c, const void *data, size_t size, void **buffer, size_t *buffer_size, size_t *buffer_allocated);
int import_compress_finish(ImportCompress *c, void **buffer, size_t *buffer_size, size_t *buffer_allocated);
