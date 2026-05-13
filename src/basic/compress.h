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
DECLARE_STRING_TABLE_LOOKUP(compression_extension, Compression);

/* Try the lowercase string table first, fall back to the uppercase one. Useful for parsing user input
 * where both forms (e.g. "xz" and "XZ") have historically been accepted. */
Compression compression_from_string_harder(const char *s);

/* Derives the compression type from a filename's extension, defaulting to COMPRESSION_NONE if the
 * filename does not carry a recognized compression suffix. */
Compression compression_from_filename(const char *filename);

bool compression_supported(Compression c);

/* Buffer size used by streaming compression APIs and pipeline stages that feed into them. Sized to
 * match the typical Linux pipe buffer so that pipeline stages don't lose throughput due to small
 * intermediate buffers. */
#define COMPRESS_PIPE_BUFFER_SIZE (128U*1024U)

#define COMPRESSION_MAGIC_BYTES_MAX 6U
Compression compression_detect_from_magic(const uint8_t data[static COMPRESSION_MAGIC_BYTES_MAX]);

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

int dlopen_xz(int log_level);
int dlopen_lz4(int log_level);
int dlopen_zstd(int log_level);
int dlopen_zlib(int log_level);
int dlopen_bzip2(int log_level);

static inline const char* default_compression_extension(void) {
        return compression_extension_to_string(DEFAULT_COMPRESSION) ?: "";
}
