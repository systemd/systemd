/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <unistd.h>

typedef enum Compression {
        COMPRESSION_NONE,
        COMPRESSION_XZ,
        COMPRESSION_LZ4,
        COMPRESSION_ZSTD,
        _COMPRESSION_MAX,
        _COMPRESSION_INVALID = -EINVAL,
} Compression;

#if defined(DEFAULT_COMPRESSION_NONE)
#define DEFAULT_COMPRESSION COMPRESSION_NONE
#elif defined(DEFAULT_COMPRESSION_XZ)
#define DEFAULT_COMPRESSION COMPRESSION_XZ
#elif defined(DEFAULT_COMPRESSION_LZ4)
#define DEFAULT_COMPRESSION COMPRESSION_LZ4
#elif defined(DEFAULT_COMPRESSION_ZSTD)
#define DEFAULT_COMPRESSION COMPRESSION_ZSTD
#else
#error "Unexpected default compression setting"
#endif

const char* compression_to_string(Compression compression);
Compression compression_from_string(const char *compression);

int compress_blob_xz(const void *src, uint64_t src_size,
                     void *dst, size_t dst_alloc_size, size_t *dst_size);
int compress_blob_lz4(const void *src, uint64_t src_size,
                      void *dst, size_t dst_alloc_size, size_t *dst_size);
int compress_blob_zstd(const void *src, uint64_t src_size,
                       void *dst, size_t dst_alloc_size, size_t *dst_size);

static inline int compress_blob(
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size) {
        int r;

#if defined(DEFAULT_COMPRESSION_ZSTD)
        r = compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size);
#elif defined(DEFAULT_COMPRESSION_LZ4)
        r = compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
#elif defined(DEFAULT_COMPRESSION_XZ)
        r = compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
#else
        r = -EOPNOTSUPP;
#endif
        if (r < 0)
                return r;

        return DEFAULT_COMPRESSION;
}

static inline int compress_blob_explicit(
                Compression compression,
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size) {
        int r;

        switch (compression) {
        case COMPRESSION_ZSTD:
                r = compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size);
                break;
        case COMPRESSION_LZ4:
                r = compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size);
                break;
        case COMPRESSION_XZ:
                r = compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size);
                break;
        case COMPRESSION_NONE:
                return -EINVAL;
        default:
                return -EOPNOTSUPP;
        }

        if (r < 0)
                return r;

        return compression;
}

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

#if defined(DEFAULT_COMPRESSION_ZSTD)
#  define compress_stream compress_stream_zstd
#  define COMPRESSED_EXT ".zst"
#elif defined(DEFAULT_COMPRESSION_LZ4)
#  define compress_stream compress_stream_lz4
#  define COMPRESSED_EXT ".lz4"
#elif defined(DEFAULT_COMPRESSION_XZ)
#  define compress_stream compress_stream_xz
#  define COMPRESSED_EXT ".xz"
#else
static inline int compress_stream(int fdf, int fdt, uint64_t max_size, uint64_t *ret_uncompressed_size) {
        return -EOPNOTSUPP;
}
#  define COMPRESSED_EXT ""
#endif

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes);
