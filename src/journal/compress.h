/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <unistd.h>

#include "journal-def.h"

const char* object_compressed_to_string(int compression);
int object_compressed_from_string(const char *compression);

int compress_blob_xz(const void *src, uint64_t src_size, void *dst, size_t *dst_size);
int compress_blob_lz4(const void *src, uint64_t src_size, void *dst, size_t *dst_size);

static inline int compress_blob(const void *src, uint64_t src_size, void *dst, size_t *dst_size) {
        int r;
#ifdef HAVE_LZ4
        r = compress_blob_lz4(src, src_size, dst, dst_size);
        if (r == 0)
                return OBJECT_COMPRESSED_LZ4;
#else
        r = compress_blob_xz(src, src_size, dst, dst_size);
        if (r == 0)
                return OBJECT_COMPRESSED_XZ;
#endif
        return r;
}

int decompress_blob_xz(const void *src, uint64_t src_size,
                       void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);
int decompress_blob_lz4(const void *src, uint64_t src_size,
                        void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);
int decompress_blob(int compression,
                    const void *src, uint64_t src_size,
                    void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);

int decompress_startswith_xz(const void *src, uint64_t src_size,
                             void **buffer, size_t *buffer_size,
                             const void *prefix, size_t prefix_len,
                             uint8_t extra);
int decompress_startswith_lz4(const void *src, uint64_t src_size,
                              void **buffer, size_t *buffer_size,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra);
int decompress_startswith(int compression,
                          const void *src, uint64_t src_size,
                          void **buffer, size_t *buffer_size,
                          const void *prefix, size_t prefix_len,
                          uint8_t extra);

int compress_stream_xz(int fdf, int fdt, uint64_t max_bytes);
int compress_stream_lz4(int fdf, int fdt, uint64_t max_bytes);

int decompress_stream_xz(int fdf, int fdt, uint64_t max_size);
int decompress_stream_lz4(int fdf, int fdt, uint64_t max_size);

#ifdef HAVE_LZ4
#  define compress_stream compress_stream_lz4
#  define COMPRESSED_EXT ".lz4"
#else
#  define compress_stream compress_stream_xz
#  define COMPRESSED_EXT ".xz"
#endif

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes);
