/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <sys/types.h>

#include <lzma.h>
#include <zlib.h>
#include <bzlib.h>

#include "macro.h"

typedef enum ImportCompressType {
        IMPORT_COMPRESS_UNKNOWN,
        IMPORT_COMPRESS_UNCOMPRESSED,
        IMPORT_COMPRESS_XZ,
        IMPORT_COMPRESS_GZIP,
        IMPORT_COMPRESS_BZIP2,
        _IMPORT_COMPRESS_TYPE_MAX,
        _IMPORT_COMPRESS_TYPE_INVALID = -1,
} ImportCompressType;

typedef struct ImportCompress {
        ImportCompressType type;
        bool encoding;
        union {
                lzma_stream xz;
                z_stream gzip;
                bz_stream bzip2;
        };
} ImportCompress;

typedef int (*ImportCompressCallback)(const void *data, size_t size, void *userdata);

void import_compress_free(ImportCompress *c);

int import_uncompress_detect(ImportCompress *c, const void *data, size_t size);
int import_uncompress(ImportCompress *c, const void *data, size_t size, ImportCompressCallback callback, void *userdata);

int import_compress_init(ImportCompress *c, ImportCompressType t);
int import_compress(ImportCompress *c, const void *data, size_t size, void **buffer, size_t *buffer_size, size_t *buffer_allocated);
int import_compress_finish(ImportCompress *c, void **buffer, size_t *buffer_size, size_t *buffer_allocated);

const char* import_compress_type_to_string(ImportCompressType t) _const_;
ImportCompressType import_compress_type_from_string(const char *s) _pure_;
