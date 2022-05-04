/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

typedef enum Compression {
        COMPRESSION_NONE,
        COMPRESSION_XZ,
        COMPRESSION_LZ4,
        COMPRESSION_ZSTD,
        _COMPRESSION_MAX,
        _COMPRESSION_INVALID = -EINVAL,
} Compression;

const char* compression_to_string(Compression compression);
Compression compression_from_string(const char *compression);

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
int decompress_blob(Compression compression,
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
int decompress_startswith(Compression compression,
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

static inline int compress_blob_explicit(
                Compression compression,
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size) {

        switch (compression) {
        case COMPRESSION_ZSTD:
                return compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size);
        case COMPRESSION_LZ4:
                return compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
        case COMPRESSION_XZ:
                return compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
        default:
                return -EOPNOTSUPP;
        }
}

#define compress_blob(src, src_size, dst, dst_alloc_size, dst_size) \
        compress_blob_explicit(                                     \
                DEFAULT_COMPRESSION,                                \
                src, src_size,                                      \
                dst, dst_alloc_size, dst_size)

static inline int compress_stream(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size) {
        switch (DEFAULT_COMPRESSION) {
        case COMPRESSION_ZSTD:
                return compress_stream_zstd(fdf, fdt, max_bytes, ret_uncompressed_size);
        case COMPRESSION_LZ4:
                return compress_stream_lz4(fdf, fdt, max_bytes, ret_uncompressed_size);
        case COMPRESSION_XZ:
                return compress_stream_xz(fdf, fdt, max_bytes, ret_uncompressed_size);
        default:
                return -EOPNOTSUPP;
        }
}

static inline const char* default_compression_extension(void) {
        switch (DEFAULT_COMPRESSION) {
        case COMPRESSION_ZSTD:
                return ".zst";
        case COMPRESSION_LZ4:
                return ".lz4";
        case COMPRESSION_XZ:
                return ".xz";
        default:
                return "";
        }
}

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes);
