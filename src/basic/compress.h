/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

typedef enum Compression {
        COMPRESSION_NONE,
        COMPRESSION_XZ,
        COMPRESSION_LZ4,
        COMPRESSION_ZSTD,
        COMPRESSION_GZIP,
        COMPRESSION_BZIP2,
        _COMPRESSION_MAX,
        _COMPRESSION_INVALID = -EINVAL,
} Compression;

DECLARE_STRING_TABLE_LOOKUP(compression, Compression);
DECLARE_STRING_TABLE_LOOKUP(compression_uppercase, Compression);

bool compression_supported(Compression c);

/* Compressor / Decompressor — opaque push-based streaming compression context */

typedef struct Compressor Compressor;
typedef Compressor Decompressor;

typedef int (*DecompressorCallback)(const void *data, size_t size, void *userdata);

Compressor* compressor_free(Compressor *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(Compressor*, compressor_free);

int compressor_new(Compressor **ret, Compression type);
int compressor_start(Compressor *c, const void *data, size_t size, void **buffer, size_t *buffer_size, size_t *buffer_allocated);
int compressor_finish(Compressor *c, void **buffer, size_t *buffer_size, size_t *buffer_allocated);

int decompressor_detect(Decompressor **ret, const void *data, size_t size);
int decompressor_force_off(Decompressor **ret);
int decompressor_push(Decompressor *c, const void *data, size_t size, DecompressorCallback callback, void *userdata);

Compression compressor_type(const Compressor *c);

/* Blob compression/decompression */

int compress_blob(Compression compression,
                  const void *src, uint64_t src_size,
                  void *dst, size_t dst_alloc_size, size_t *dst_size, int level);
int decompress_blob(Compression compression,
                    const void *src, uint64_t src_size,
                    void **dst, size_t *dst_size, size_t dst_max);

int decompress_zlib_raw(const void *src, uint64_t src_size,
                        void *dst, size_t dst_size, int wbits);

int decompress_startswith(Compression compression,
                          const void *src, uint64_t src_size,
                          void **buffer,
                          const void *prefix, size_t prefix_len,
                          uint8_t extra);

/* Stream compression/decompression (fd-to-fd) */

int compress_stream(Compression type, int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size);
int decompress_stream(Compression type, int fdf, int fdt, uint64_t max_bytes);
int decompress_stream_by_filename(const char *filename, int fdf, int fdt, uint64_t max_bytes);

int dlopen_xz(void);
int dlopen_lz4(void);
int dlopen_zstd(void);
int dlopen_zlib(void);
int dlopen_bzip2(void);

static inline const char* default_compression_extension(void) {
        switch (DEFAULT_COMPRESSION) {
        case COMPRESSION_XZ:
                return ".xz";
        case COMPRESSION_LZ4:
                return ".lz4";
        case COMPRESSION_ZSTD:
                return ".zst";
        case COMPRESSION_GZIP:
                return ".gz";
        case COMPRESSION_BZIP2:
                return ".bz2";
        default:
                return "";
        }
}
