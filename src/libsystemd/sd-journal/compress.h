/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <unistd.h>

#include "journal-def.h"

const char* object_compressed_to_string(int compression);
int object_compressed_from_string(const char *compression);

int compress_blob_xz(const void *src, uint64_t src_size,
                     void *dst, size_t dst_alloc_size, size_t *dst_size);
int compress_blob_lz4(const void *src, uint64_t src_size,
                      void *dst, size_t dst_alloc_size, size_t *dst_size);
int compress_blob_zstd(const void *src, uint64_t src_size,
                       void *dst, size_t dst_alloc_size, size_t *dst_size);

static inline int compress_blob(const void *src, uint64_t src_size,
                                void *dst, size_t dst_alloc_size, size_t *dst_size) {
        int r;
#if HAVE_ZSTD
        r = compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size);
        if (r == 0)
                return OBJECT_COMPRESSED_ZSTD;
#elif HAVE_LZ4
        r = compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
        if (r == 0)
                return OBJECT_COMPRESSED_LZ4;
#elif HAVE_XZ
        r = compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
        if (r == 0)
                return OBJECT_COMPRESSED_XZ;
#else
        r = -EOPNOTSUPP;
#endif
        return r;
}

int decompress_blob_xz(const void *src, uint64_t src_size,
                       void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);
int decompress_blob_lz4(const void *src, uint64_t src_size,
                        void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max);
int decompress_blob_zstd(const void *src, uint64_t src_size,
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
int decompress_startswith_zstd(const void *src, uint64_t src_size,
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
int compress_stream_zstd(int fdf, int fdt, uint64_t max_bytes);

int decompress_stream_xz(int fdf, int fdt, uint64_t max_size);
int decompress_stream_lz4(int fdf, int fdt, uint64_t max_size);
int decompress_stream_zstd(int fdf, int fdt, uint64_t max_size);

#if HAVE_ZSTD
#  define compress_stream compress_stream_zstd
#  define COMPRESSED_EXT ".zst"
#elif HAVE_LZ4
#  define compress_stream compress_stream_lz4
#  define COMPRESSED_EXT ".lz4"
#elif HAVE_XZ
#  define compress_stream compress_stream_xz
#  define COMPRESSED_EXT ".xz"
#else
static inline int compress_stream(int fdf, int fdt, uint64_t max_size) {
        return -EOPNOTSUPP;
}
#  define COMPRESSED_EXT ""
#endif

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes);
