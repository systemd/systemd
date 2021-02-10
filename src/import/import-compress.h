/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_BZIP2
#include <bzlib.h>
#endif
#include <lzma.h>
#include <sys/types.h>
#include <zlib.h>

#include "macro.h"

typedef enum ImportCompressType {
        IMPORT_COMPRESS_UNKNOWN,
        IMPORT_COMPRESS_UNCOMPRESSED,
        IMPORT_COMPRESS_XZ,
        IMPORT_COMPRESS_GZIP,
        IMPORT_COMPRESS_BZIP2,
        _IMPORT_COMPRESS_TYPE_MAX,
        _IMPORT_COMPRESS_TYPE_INVALID = -EINVAL,
} ImportCompressType;

typedef struct ImportCompress {
        ImportCompressType type;
        bool encoding;
        union {
                lzma_stream xz;
                z_stream gzip;
#if HAVE_BZIP2
                bz_stream bzip2;
#endif
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

const char* import_compress_type_to_string(ImportCompressType t) _const_;
ImportCompressType import_compress_type_from_string(const char *s) _pure_;
