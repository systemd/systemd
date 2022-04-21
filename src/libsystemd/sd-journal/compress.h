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

int decompress_blob_xz(const void *src, uint64_t src_size,
                       void **dst, size_t* dst_size, size_t dst_max);
int decompress_blob_lz4(const void *src, uint64_t src_size,
                        void **dst, size_t* dst_size, size_t dst_max);
int decompress_blob_zstd(const void *src, uint64_t src_size,
                        void **dst, size_t* dst_size, size_t dst_max);
int decompress_blob(int compression,
                    const void *src, uint64_t src_size,
                    void **dst, size_t* dst_size, size_t dst_max);

int decompress_startswith_xz(const void *src, uint64_t src_size,
                             void **buffer,
                             const void *prefix, size_t prefix_len,
                             uint8_t extra);
int decompress_startswith_lz4(const void *src, uint64_t src_size,
                              void **buffer,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra);
int decompress_startswith_zstd(const void *src, uint64_t src_size,
                               void **buffer,
                               const void *prefix, size_t prefix_len,
                               uint8_t extra);
int decompress_startswith(int compression,
                          const void *src, uint64_t src_size,
                          void **buffer,
                          const void *prefix, size_t prefix_len,
                          uint8_t extra);

int compress_stream_xz(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size);
int compress_stream_lz4(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size);
int compress_stream_zstd(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size);

int decompress_stream_xz(int fdf, int fdt, uint64_t max_size);
int decompress_stream_lz4(int fdf, int fdt, uint64_t max_size);
int decompress_stream_zstd(int fdf, int fdt, uint64_t max_size);

static inline int compress_blob(const void *src, uint64_t src_size,
                                void *dst, size_t dst_alloc_size, size_t *dst_size) {
#if DEFAULT_COMPRESSION_ZSTD
        return compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size);
#elif DEFAULT_COMPRESSION_LZ4
        return compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
#elif DEFAULT_COMPRESSION_XZ
        return compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
#else
        return -EOPNOTSUPP;
#endif
}

static inline int compress_stream(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size) {
#if DEFAULT_COMPRESSION_ZSTD
        return compress_stream_zstd(fdf, fdt, max_bytes, ret_uncompressed_size);
#elif DEFAULT_COMPRESSION_LZ4
        return compress_stream_lz4(fdf, fdt, max_bytes, ret_uncompressed_size);
#elif DEFAULT_COMPRESSION_XZ
        return compress_stream_xz(fdf, fdt, max_bytes, ret_uncompressed_size);
#else
        return -EOPNOTSUPP;
#endif
}

#if DEFAULT_COMPRESSION_ZSTD
#  define COMPRESSED_EXT ".zst"
#elif DEFAULT_COMPRESSION_LZ4
#  define COMPRESSED_EXT ".lz4"
#elif DEFAULT_COMPRESSION_XZ
#  define COMPRESSED_EXT ".xz"
#else
#  define COMPRESSED_EXT ""
#endif

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes);
