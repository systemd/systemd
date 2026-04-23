/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#if HAVE_XZ
#include <lzma.h>
#endif

#if HAVE_LZ4
#include <lz4.h>
#include <lz4frame.h>
#include <lz4hc.h>
#endif

#if HAVE_ZSTD
#include <zstd.h>
#include <zstd_errors.h>
#endif

#if HAVE_ZLIB
#include <zlib.h>
#endif

#if HAVE_BZIP2
#include <bzlib.h>
#endif

#include "sd-dlopen.h"

#include "alloc-util.h"
#include "bitfield.h"
#include "compress.h"
#include "dlfcn-util.h"
#include "io-util.h"
#include "log.h"
#include "string-table.h"
#include "unaligned.h"

#if HAVE_XZ
static void *lzma_dl = NULL;

static DLSYM_PROTOTYPE(lzma_code) = NULL;
static DLSYM_PROTOTYPE(lzma_easy_encoder) = NULL;
static DLSYM_PROTOTYPE(lzma_end) = NULL;
static DLSYM_PROTOTYPE(lzma_stream_buffer_encode) = NULL;
static DLSYM_PROTOTYPE(lzma_stream_decoder) = NULL;
static DLSYM_PROTOTYPE(lzma_lzma_preset) = NULL;

/* We can’t just do _cleanup_(sym_lzma_end) because a compiler bug makes
 * this fail with:
 * ../src/basic/compress.c: In function ‘decompress_blob_xz’:
 * ../src/basic/compress.c:304:9: error: cleanup argument not a function
 *   304 |         _cleanup_(sym_lzma_end) lzma_stream s = LZMA_STREAM_INIT;
 *       |         ^~~~~~~~~
 */
static inline void lzma_end_wrapper(lzma_stream *ls) {
        sym_lzma_end(ls);
}
#endif

#if HAVE_LZ4
static void *lz4_dl = NULL;

static DLSYM_PROTOTYPE(LZ4F_compressBegin) = NULL;
static DLSYM_PROTOTYPE(LZ4F_compressBound) = NULL;
static DLSYM_PROTOTYPE(LZ4F_compressEnd) = NULL;
static DLSYM_PROTOTYPE(LZ4F_compressUpdate) = NULL;
static DLSYM_PROTOTYPE(LZ4F_createCompressionContext) = NULL;
static DLSYM_PROTOTYPE(LZ4F_createDecompressionContext) = NULL;
static DLSYM_PROTOTYPE(LZ4F_decompress) = NULL;
static DLSYM_PROTOTYPE(LZ4F_freeCompressionContext) = NULL;
static DLSYM_PROTOTYPE(LZ4F_freeDecompressionContext) = NULL;
static DLSYM_PROTOTYPE(LZ4F_isError) = NULL;
static DLSYM_PROTOTYPE(LZ4_compress_HC) = NULL;
static DLSYM_PROTOTYPE(LZ4_compress_default) = NULL;
static DLSYM_PROTOTYPE(LZ4_decompress_safe) = NULL;
static DLSYM_PROTOTYPE(LZ4_decompress_safe_partial) = NULL;
static DLSYM_PROTOTYPE(LZ4_versionNumber) = NULL;

static const LZ4F_preferences_t lz4_preferences = {
        .frameInfo.blockSizeID = 5,
};
#endif

#if HAVE_ZSTD
static void *zstd_dl = NULL;

static DLSYM_PROTOTYPE(ZSTD_CCtx_setParameter) = NULL;
static DLSYM_PROTOTYPE(ZSTD_compress) = NULL;
static DLSYM_PROTOTYPE(ZSTD_compressStream2) = NULL;
static DLSYM_PROTOTYPE(ZSTD_createCCtx) = NULL;
static DLSYM_PROTOTYPE(ZSTD_createDCtx) = NULL;
static DLSYM_PROTOTYPE(ZSTD_CStreamInSize) = NULL;
static DLSYM_PROTOTYPE(ZSTD_CStreamOutSize) = NULL;
static DLSYM_PROTOTYPE(ZSTD_decompressStream) = NULL;
static DLSYM_PROTOTYPE(ZSTD_DStreamInSize) = NULL;
static DLSYM_PROTOTYPE(ZSTD_DStreamOutSize) = NULL;
static DLSYM_PROTOTYPE(ZSTD_freeCCtx) = NULL;
static DLSYM_PROTOTYPE(ZSTD_freeDCtx) = NULL;
static DLSYM_PROTOTYPE(ZSTD_getErrorCode) = NULL;
static DLSYM_PROTOTYPE(ZSTD_getErrorName) = NULL;
static DLSYM_PROTOTYPE(ZSTD_getFrameContentSize) = NULL;
static DLSYM_PROTOTYPE(ZSTD_isError) = NULL;

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL_RENAME(ZSTD_DCtx*, sym_ZSTD_freeDCtx, ZSTD_freeDCtxp, NULL);

static int zstd_ret_to_errno(size_t ret) {
        switch (sym_ZSTD_getErrorCode(ret)) {
        case ZSTD_error_dstSize_tooSmall:
                return -ENOBUFS;
        case ZSTD_error_memory_allocation:
                return -ENOMEM;
        default:
                return -EBADMSG;
        }
}
#endif

#if HAVE_ZLIB
static void *zlib_dl = NULL;

static DLSYM_PROTOTYPE(deflateInit2_) = NULL;
static DLSYM_PROTOTYPE(deflate) = NULL;
static DLSYM_PROTOTYPE(deflateEnd) = NULL;
static DLSYM_PROTOTYPE(inflateInit2_) = NULL;
static DLSYM_PROTOTYPE(inflate) = NULL;
static DLSYM_PROTOTYPE(inflateEnd) = NULL;

static inline void deflateEnd_wrapper(z_stream *s) {
        sym_deflateEnd(s);
}

static inline void inflateEnd_wrapper(z_stream *s) {
        sym_inflateEnd(s);
}
#endif

#if HAVE_BZIP2
static void *bzip2_dl = NULL;

static DLSYM_PROTOTYPE(BZ2_bzCompressInit) = NULL;
static DLSYM_PROTOTYPE(BZ2_bzCompress) = NULL;
static DLSYM_PROTOTYPE(BZ2_bzCompressEnd) = NULL;
static DLSYM_PROTOTYPE(BZ2_bzDecompressInit) = NULL;
static DLSYM_PROTOTYPE(BZ2_bzDecompress) = NULL;
static DLSYM_PROTOTYPE(BZ2_bzDecompressEnd) = NULL;

static inline void BZ2_bzCompressEnd_wrapper(bz_stream *s) {
        sym_BZ2_bzCompressEnd(s);
}

static inline void BZ2_bzDecompressEnd_wrapper(bz_stream *s) {
        sym_BZ2_bzDecompressEnd(s);
}
#endif

/* Opaque Compressor/Decompressor struct definition */
struct Compressor {
        Compression type;
        bool encoding;
        union {
#if HAVE_XZ
                lzma_stream xz;
#endif
#if HAVE_LZ4
                struct {
                        LZ4F_compressionContext_t c_lz4;
                        void *lz4_header;        /* stashed frame header from LZ4F_compressBegin */
                        size_t lz4_header_size;
                };
                LZ4F_decompressionContext_t d_lz4;
#endif
#if HAVE_ZSTD
                ZSTD_CCtx *c_zstd;
                ZSTD_DCtx *d_zstd;
#endif
#if HAVE_ZLIB
                z_stream gzip;
#endif
#if HAVE_BZIP2
                bz_stream bzip2;
#endif
        };
};

#define ALIGN_8(l) ALIGN_TO(l, sizeof(size_t))

/* zlib windowBits value for gzip format: MAX_WBITS (15) + 16 to enable gzip header detection/generation */
#define ZLIB_WBITS_GZIP (15 + 16)

static const char* const compression_table[_COMPRESSION_MAX] = {
        [COMPRESSION_NONE]  = "uncompressed", /* backwards compatibility with importd */
        [COMPRESSION_XZ]    = "xz",
        [COMPRESSION_LZ4]   = "lz4",
        [COMPRESSION_ZSTD]  = "zstd",
        [COMPRESSION_GZIP]  = "gzip",
        [COMPRESSION_BZIP2] = "bzip2",
};

static const char* const compression_uppercase_table[_COMPRESSION_MAX] = {
        [COMPRESSION_NONE]  = "NONE", /* backwards compatibility with SYSTEMD_JOURNAL_COMPRESS=NONE */
        [COMPRESSION_XZ]    = "XZ",
        [COMPRESSION_LZ4]   = "LZ4",
        [COMPRESSION_ZSTD]  = "ZSTD",
        [COMPRESSION_GZIP]  = "GZIP",
        [COMPRESSION_BZIP2] = "BZIP2",
};

static const char* const compression_extension_table[_COMPRESSION_MAX] = {
        [COMPRESSION_NONE]  = "",
        [COMPRESSION_XZ]    = ".xz",
        [COMPRESSION_LZ4]   = ".lz4",
        [COMPRESSION_ZSTD]  = ".zst",
        [COMPRESSION_GZIP]  = ".gz",
        [COMPRESSION_BZIP2] = ".bz2",
};

DEFINE_STRING_TABLE_LOOKUP(compression, Compression);
DEFINE_STRING_TABLE_LOOKUP(compression_uppercase, Compression);
DEFINE_STRING_TABLE_LOOKUP(compression_extension, Compression);

Compression compression_from_string_harder(const char *s) {
        Compression c;

        assert(s);

        c = compression_from_string(s);
        if (c >= 0)
                return c;

        return compression_uppercase_from_string(s);
}

Compression compression_from_filename(const char *filename) {
        Compression c;
        const char *e;

        assert(filename);

        e = strrchr(filename, '.');
        if (!e)
                return COMPRESSION_NONE;

        c = compression_extension_from_string(e);
        if (c < 0)
                return COMPRESSION_NONE;

        return c;
}

bool compression_supported(Compression c) {
        static const unsigned supported =
                (1U << COMPRESSION_NONE) |
                (1U << COMPRESSION_XZ) * HAVE_XZ |
                (1U << COMPRESSION_LZ4) * HAVE_LZ4 |
                (1U << COMPRESSION_ZSTD) * HAVE_ZSTD |
                (1U << COMPRESSION_GZIP) * HAVE_ZLIB |
                (1U << COMPRESSION_BZIP2) * HAVE_BZIP2;

        assert(c >= 0);
        assert(c < _COMPRESSION_MAX);

        return BIT_SET(supported, c);
}

Compression compression_detect_from_magic(const uint8_t data[static COMPRESSION_MAGIC_BYTES_MAX]) {
        /* Magic signatures per RFC 1952 (gzip), tukaani.org/xz/xz-file-format.txt (xz),
         * RFC 8878 (zstd), lz4/doc/lz4_Frame_format.md (lz4), and the bzip2 file format.
         * Make sure to update COMPRESSION_MAGIC_BYTES_MAX if needed when adding a new magic. */
        if (memcmp(data, (const uint8_t[]) { 0x1f, 0x8b }, 2) == 0)
                return COMPRESSION_GZIP;
        if (memcmp(data, (const uint8_t[]) { 0xfd, '7', 'z', 'X', 'Z', 0x00 }, 6) == 0)
                return COMPRESSION_XZ;
        if (memcmp(data, (const uint8_t[]) { 0x28, 0xb5, 0x2f, 0xfd }, 4) == 0)
                return COMPRESSION_ZSTD;
        if (memcmp(data, (const uint8_t[]) { 0x04, 0x22, 0x4d, 0x18 }, 4) == 0)
                return COMPRESSION_LZ4;
        if (memcmp(data, (const uint8_t[]) { 'B', 'Z', 'h' }, 3) == 0)
                return COMPRESSION_BZIP2;

        return _COMPRESSION_INVALID;
}

int dlopen_xz(int log_level) {
#if HAVE_XZ
        SD_ELF_NOTE_DLOPEN(
                        "lzma",
                        "Support lzma compression in journal and coredump files",
                        COMPRESSION_PRIORITY_XZ,
                        "liblzma.so.5");

        return dlopen_many_sym_or_warn(
                        &lzma_dl,
                        "liblzma.so.5", log_level,
                        DLSYM_ARG(lzma_code),
                        DLSYM_ARG(lzma_easy_encoder),
                        DLSYM_ARG(lzma_end),
                        DLSYM_ARG(lzma_stream_buffer_encode),
                        DLSYM_ARG(lzma_lzma_preset),
                        DLSYM_ARG(lzma_stream_decoder));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "lzma support is not compiled in.");
#endif
}

int dlopen_lz4(int log_level) {
#if HAVE_LZ4
        SD_ELF_NOTE_DLOPEN(
                        "lz4",
                        "Support lz4 compression in journal and coredump files",
                        COMPRESSION_PRIORITY_LZ4,
                        "liblz4.so.1");

        return dlopen_many_sym_or_warn(
                        &lz4_dl,
                        "liblz4.so.1", log_level,
                        DLSYM_ARG(LZ4F_compressBegin),
                        DLSYM_ARG(LZ4F_compressBound),
                        DLSYM_ARG(LZ4F_compressEnd),
                        DLSYM_ARG(LZ4F_compressUpdate),
                        DLSYM_ARG(LZ4F_createCompressionContext),
                        DLSYM_ARG(LZ4F_createDecompressionContext),
                        DLSYM_ARG(LZ4F_decompress),
                        DLSYM_ARG(LZ4F_freeCompressionContext),
                        DLSYM_ARG(LZ4F_freeDecompressionContext),
                        DLSYM_ARG(LZ4F_isError),
                        DLSYM_ARG(LZ4_compress_default),
                        DLSYM_ARG(LZ4_compress_HC),
                        DLSYM_ARG(LZ4_decompress_safe),
                        DLSYM_ARG(LZ4_decompress_safe_partial),
                        DLSYM_ARG(LZ4_versionNumber));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "lz4 support is not compiled in.");
#endif
}

int dlopen_zstd(int log_level) {
#if HAVE_ZSTD
        SD_ELF_NOTE_DLOPEN(
                        "zstd",
                        "Support zstd compression in journal and coredump files",
                        COMPRESSION_PRIORITY_ZSTD,
                        "libzstd.so.1");

        return dlopen_many_sym_or_warn(
                        &zstd_dl,
                        "libzstd.so.1", log_level,
                        DLSYM_ARG(ZSTD_getErrorCode),
                        DLSYM_ARG(ZSTD_compress),
                        DLSYM_ARG(ZSTD_getFrameContentSize),
                        DLSYM_ARG(ZSTD_decompressStream),
                        DLSYM_ARG(ZSTD_getErrorName),
                        DLSYM_ARG(ZSTD_DStreamOutSize),
                        DLSYM_ARG(ZSTD_CStreamInSize),
                        DLSYM_ARG(ZSTD_CStreamOutSize),
                        DLSYM_ARG(ZSTD_CCtx_setParameter),
                        DLSYM_ARG(ZSTD_compressStream2),
                        DLSYM_ARG(ZSTD_DStreamInSize),
                        DLSYM_ARG(ZSTD_freeCCtx),
                        DLSYM_ARG(ZSTD_freeDCtx),
                        DLSYM_ARG(ZSTD_isError),
                        DLSYM_ARG(ZSTD_createDCtx),
                        DLSYM_ARG(ZSTD_createCCtx));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "zstd support is not compiled in.");
#endif
}

int dlopen_zlib(int log_level) {
#if HAVE_ZLIB
        SD_ELF_NOTE_DLOPEN(
                        "zlib",
                        "Support gzip compression and decompression",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libz.so.1");

        return dlopen_many_sym_or_warn(
                        &zlib_dl,
                        "libz.so.1", log_level,
                        DLSYM_ARG(deflateInit2_),
                        DLSYM_ARG(deflate),
                        DLSYM_ARG(deflateEnd),
                        DLSYM_ARG(inflateInit2_),
                        DLSYM_ARG(inflate),
                        DLSYM_ARG(inflateEnd));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "zlib support is not compiled in.");
#endif
}

int dlopen_bzip2(int log_level) {
#if HAVE_BZIP2
        SD_ELF_NOTE_DLOPEN(
                        "bzip2",
                        "Support bzip2 compression and decompression",
                        SD_ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libbz2.so.1");

        return dlopen_many_sym_or_warn(
                        &bzip2_dl,
                        "libbz2.so.1", log_level,
                        DLSYM_ARG(BZ2_bzCompressInit),
                        DLSYM_ARG(BZ2_bzCompress),
                        DLSYM_ARG(BZ2_bzCompressEnd),
                        DLSYM_ARG(BZ2_bzDecompressInit),
                        DLSYM_ARG(BZ2_bzDecompress),
                        DLSYM_ARG(BZ2_bzDecompressEnd));
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "bzip2 support is not compiled in.");
#endif
}

static int compress_blob_xz(
                const void *src,
                uint64_t src_size,
                void *dst,
                size_t dst_alloc_size,
                size_t *dst_size,
                int level) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_XZ
        lzma_options_lzma opt = {
                1u << 20u, NULL, 0, LZMA_LC_DEFAULT, LZMA_LP_DEFAULT,
                LZMA_PB_DEFAULT, LZMA_MODE_FAST, 128, LZMA_MF_HC3, 4
        };
        lzma_filter filters[] = {
                { LZMA_FILTER_LZMA2, &opt },
                { LZMA_VLI_UNKNOWN, NULL }
        };
        lzma_ret ret;
        size_t out_pos = 0;
        int r;

        r = dlopen_xz(LOG_DEBUG);
        if (r < 0)
                return r;

        if (level >= 0) {
                r = sym_lzma_lzma_preset(&opt, (uint32_t) level);
                if (r < 0)
                        return r;
        }

        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 80)
                return -ENOBUFS;

        ret = sym_lzma_stream_buffer_encode(filters, LZMA_CHECK_NONE, NULL,
                                        src, src_size, dst, &out_pos, dst_alloc_size);
        if (ret != LZMA_OK)
                return -ENOBUFS;

        *dst_size = out_pos;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int compress_blob_lz4(
                const void *src,
                uint64_t src_size,
                void *dst,
                size_t dst_alloc_size,
                size_t *dst_size,
                int level) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_LZ4
        int r;

        r = dlopen_lz4(LOG_DEBUG);
        if (r < 0)
                return r;
        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 9)
                return -ENOBUFS;

        if (src_size > INT_MAX)
                return -EFBIG;
        if (dst_alloc_size > INT_MAX)
                dst_alloc_size = INT_MAX;

        if (level <= 0)
                r = sym_LZ4_compress_default(src, (char*)dst + 8, src_size, (int) dst_alloc_size - 8);
        else
                r = sym_LZ4_compress_HC(src, (char*)dst + 8, src_size, (int) dst_alloc_size - 8, level);
        if (r <= 0)
                return -ENOBUFS;

        unaligned_write_le64(dst, src_size);
        *dst_size = r + 8;

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int compress_blob_zstd(
                const void *src,
                uint64_t src_size,
                void *dst,
                size_t dst_alloc_size,
                size_t *dst_size,
                int level) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_ZSTD
        size_t k;
        int r;

        r = dlopen_zstd(LOG_DEBUG);
        if (r < 0)
                return r;

        k = sym_ZSTD_compress(dst, dst_alloc_size, src, src_size, level < 0 ? 0 : level);
        if (sym_ZSTD_isError(k))
                return zstd_ret_to_errno(k);

        *dst_size = k;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int compress_blob_gzip(const void *src, uint64_t src_size,
                       void *dst, size_t dst_alloc_size, size_t *dst_size, int level) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_ZLIB
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;
        if (dst_alloc_size > UINT_MAX)
                dst_alloc_size = UINT_MAX;

        _cleanup_(deflateEnd_wrapper) z_stream s = {};

        r = sym_deflateInit2_(&s, level < 0 ? Z_DEFAULT_COMPRESSION : level,
                              /* method= */ Z_DEFLATED,
                              /* windowBits= */ ZLIB_WBITS_GZIP,
                              /* memLevel= */ 8,
                              /* strategy= */ Z_DEFAULT_STRATEGY,
                              ZLIB_VERSION, (int) sizeof(s));
        if (r != Z_OK)
                return -ENOMEM;

        s.next_in = (void*) src;
        s.avail_in = src_size;
        s.next_out = dst;
        s.avail_out = dst_alloc_size;

        r = sym_deflate(&s, Z_FINISH);
        if (r != Z_STREAM_END)
                return -ENOBUFS;

        *dst_size = dst_alloc_size - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int compress_blob_bzip2(
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size, int level) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_BZIP2
        int r;

        r = dlopen_bzip2(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;
        if (dst_alloc_size > UINT_MAX)
                dst_alloc_size = UINT_MAX;

        _cleanup_(BZ2_bzCompressEnd_wrapper) bz_stream s = {};

        r = sym_BZ2_bzCompressInit(&s, level < 0 ? 9 : level, /* verbosity= */ 0, /* workFactor= */ 0);
        if (r != BZ_OK)
                return -ENOMEM;

        s.next_in = (char*) src;
        s.avail_in = src_size;
        s.next_out = (char*) dst;
        s.avail_out = dst_alloc_size;

        r = sym_BZ2_bzCompress(&s, BZ_FINISH);

        if (r != BZ_STREAM_END)
                return -ENOBUFS;

        *dst_size = dst_alloc_size - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int compress_blob(
                Compression compression,
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size, int level) {

        switch (compression) {
        case COMPRESSION_XZ:
                return compress_blob_xz(src, src_size, dst, dst_alloc_size, dst_size, level);
        case COMPRESSION_LZ4:
                return compress_blob_lz4(src, src_size, dst, dst_alloc_size, dst_size, level);
        case COMPRESSION_ZSTD:
                return compress_blob_zstd(src, src_size, dst, dst_alloc_size, dst_size, level);
        case COMPRESSION_GZIP:
                return compress_blob_gzip(src, src_size, dst, dst_alloc_size, dst_size, level);
        case COMPRESSION_BZIP2:
                return compress_blob_bzip2(src, src_size, dst, dst_alloc_size, dst_size, level);
        default:
                return -EOPNOTSUPP;
        }
}

static int decompress_blob_xz(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_XZ
        int r;

        r = dlopen_xz(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret = sym_lzma_stream_decoder(&s, UINT64_MAX, /* flags= */ 0);
        if (ret != LZMA_OK)
                return -ENOMEM;

        size_t space = MIN(src_size * 2, dst_max ?: SIZE_MAX);
        if (!greedy_realloc(dst, space, 1))
                return -ENOMEM;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *dst;
        s.avail_out = space;

        for (;;) {
                size_t used;

                ret = sym_lzma_code(&s, LZMA_FINISH);
                if (ret == LZMA_STREAM_END)
                        break;
                if (ret != LZMA_OK)
                        return -ENOMEM;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
                /* Silence static analyzers, space is bounded by allocation size */
                assert(space <= SIZE_MAX / 2);
                space = MIN(2 * space, dst_max ?: SIZE_MAX);
                if (!greedy_realloc(dst, space, 1))
                        return -ENOMEM;

                s.avail_out = space - used;
                s.next_out = *(uint8_t**)dst + used;
        }

        *dst_size = space - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_blob_lz4(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_LZ4
        char* out;
        int r, size; /* LZ4 uses int for size */

        r = dlopen_lz4(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size <= 8)
                return -EBADMSG;

        if (src_size - 8 > INT_MAX)
                return -EFBIG;

        size = unaligned_read_le64(src);
        if (size < 0 || (unsigned) size != unaligned_read_le64(src))
                return -EFBIG;
        if (dst_max > 0 && (size_t) size > dst_max)
                return -ENOBUFS;
        out = greedy_realloc(dst, size, 1);
        if (!out)
                return -ENOMEM;

        r = sym_LZ4_decompress_safe((char*)src + 8, out, src_size - 8, size);
        if (r < 0 || r != size)
                return -EBADMSG;

        *dst_size = size;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_blob_zstd(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_ZSTD
        uint64_t size;
        int r;

        r = dlopen_zstd(LOG_DEBUG);
        if (r < 0)
                return r;

        size = sym_ZSTD_getFrameContentSize(src, src_size);
        if (IN_SET(size, ZSTD_CONTENTSIZE_ERROR, ZSTD_CONTENTSIZE_UNKNOWN))
                return -EBADMSG;

        if (dst_max > 0 && size > dst_max)
                size = dst_max;
        if (size > SIZE_MAX)
                return -E2BIG;

        if (!(greedy_realloc(dst, MAX(sym_ZSTD_DStreamOutSize(), size), 1)))
                return -ENOMEM;

        _cleanup_(ZSTD_freeDCtxp) ZSTD_DCtx *dctx = sym_ZSTD_createDCtx();
        if (!dctx)
                return -ENOMEM;

        ZSTD_inBuffer input = {
                .src = src,
                .size = src_size,
        };
        ZSTD_outBuffer output = {
                .dst = *dst,
                .size = MALLOC_SIZEOF_SAFE(*dst),
        };

        size_t k = sym_ZSTD_decompressStream(dctx, &output, &input);
        if (sym_ZSTD_isError(k))
                return log_debug_errno(zstd_ret_to_errno(k), "ZSTD decoder failed: %s", sym_ZSTD_getErrorName(k));
        if (output.pos < size)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "ZSTD decoded less data than indicated, probably corrupted stream.");

        *dst_size = size;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_blob_gzip(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_ZLIB
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;

        _cleanup_(inflateEnd_wrapper) z_stream s = {};

        r = sym_inflateInit2_(&s, /* windowBits= */ ZLIB_WBITS_GZIP, ZLIB_VERSION, (int) sizeof(s));
        if (r != Z_OK)
                return -ENOMEM;

        size_t space = MIN3(src_size * 2, dst_max ?: SIZE_MAX, (size_t) UINT_MAX);
        if (!greedy_realloc(dst, space, 1))
                return -ENOMEM;

        s.next_in = (void*) src;
        s.avail_in = src_size;
        s.next_out = *dst;
        s.avail_out = space;

        for (;;) {
                size_t used;

                r = sym_inflate(&s, Z_NO_FLUSH);
                if (r == Z_STREAM_END)
                        break;
                if (!IN_SET(r, Z_OK, Z_BUF_ERROR))
                        return -EBADMSG;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
                space = MIN3(2 * space, dst_max ?: SIZE_MAX, UINT_MAX);
                if (!greedy_realloc(dst, space, 1))
                        return -ENOMEM;

                s.avail_out = space - used;
                s.next_out = *(uint8_t**)dst + used;
        }

        *dst_size = space - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_blob_bzip2(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_BZIP2
        int r;

        r = dlopen_bzip2(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;

        _cleanup_(BZ2_bzDecompressEnd_wrapper) bz_stream s = {};

        r = sym_BZ2_bzDecompressInit(&s, /* verbosity= */ 0, /* small= */ 0);
        if (r != BZ_OK)
                return -ENOMEM;

        size_t space = MIN3(src_size * 2, dst_max ?: SIZE_MAX, (size_t) UINT_MAX);
        if (!greedy_realloc(dst, space, 1))
                return -ENOMEM;

        s.next_in = (char*) src;
        s.avail_in = src_size;
        s.next_out = (char*) *dst;
        s.avail_out = space;

        for (;;) {
                size_t used;

                r = sym_BZ2_bzDecompress(&s);
                if (r == BZ_STREAM_END)
                        break;
                if (r != BZ_OK)
                        return -EBADMSG;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
                space = MIN3(2 * space, dst_max ?: SIZE_MAX, (size_t) UINT_MAX);
                if (!greedy_realloc(dst, space, 1))
                        return -ENOMEM;

                s.avail_out = space - used;
                s.next_out = (char*) *dst + used;
        }

        *dst_size = space - s.avail_out;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob(
                Compression compression,
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t *dst_size,
                size_t dst_max) {

        switch (compression) {
        case COMPRESSION_XZ:
                return decompress_blob_xz(
                                src, src_size,
                                dst, dst_size, dst_max);
        case COMPRESSION_LZ4:
                return decompress_blob_lz4(
                                src, src_size,
                                dst, dst_size, dst_max);
        case COMPRESSION_ZSTD:
                return decompress_blob_zstd(
                                src, src_size,
                                dst, dst_size, dst_max);
        case COMPRESSION_GZIP:
                return decompress_blob_gzip(
                                src, src_size,
                                dst, dst_size, dst_max);
        case COMPRESSION_BZIP2:
                return decompress_blob_bzip2(
                                src, src_size,
                                dst, dst_size, dst_max);
        default:
                return -EPROTONOSUPPORT;
        }
}

int decompress_zlib_raw(
                const void *src,
                uint64_t src_size,
                void *dst,
                size_t dst_size,
                int wbits) {

#if HAVE_ZLIB
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;
        if (dst_size > UINT_MAX)
                return -EFBIG;

        _cleanup_(inflateEnd_wrapper) z_stream s = {
                .next_in = (void*) src,
                .avail_in = src_size,
                .next_out = dst,
                .avail_out = dst_size,
        };

        r = sym_inflateInit2_(&s, /* windowBits= */ wbits, ZLIB_VERSION, (int) sizeof(s));
        if (r != Z_OK)
                return -EIO;

        r = sym_inflate(&s, Z_FINISH);
        size_t produced = (uint8_t*) s.next_out - (uint8_t*) dst;

        if (r != Z_STREAM_END || produced != dst_size)
                return -EBADMSG;

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_startswith_xz(
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        /* Checks whether the decompressed blob starts with the mentioned prefix. The byte extra needs to
         * follow the prefix */

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(prefix);

#if HAVE_XZ
        int r;

        r = dlopen_xz(LOG_DEBUG);
        if (r < 0)
                return r;

        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret = sym_lzma_stream_decoder(&s, UINT64_MAX, /* flags= */ 0);
        if (ret != LZMA_OK)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        size_t allocated = MALLOC_SIZEOF_SAFE(*buffer);

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = allocated;

        for (;;) {
                ret = sym_lzma_code(&s, LZMA_FINISH);

                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END))
                        return -EBADMSG;

                if (allocated - s.avail_out >= prefix_len + 1)
                        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                                ((const uint8_t*) *buffer)[prefix_len] == extra;

                if (ret == LZMA_STREAM_END)
                        return 0;

                s.avail_out += allocated;

                if (!(greedy_realloc(buffer, allocated * 2, 1)))
                        return -ENOMEM;

                allocated = MALLOC_SIZEOF_SAFE(*buffer);
                s.next_out = *(uint8_t**)buffer + allocated - s.avail_out;
        }

#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_startswith_lz4(
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        /* Checks whether the decompressed blob starts with the mentioned prefix. The byte extra needs to
         * follow the prefix */

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(prefix);

#if HAVE_LZ4
        size_t allocated;
        int r;

        r = dlopen_lz4(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size <= 8)
                return -EBADMSG;

        if (src_size - 8 > INT_MAX)
                return -EFBIG;

        if (!(greedy_realloc(buffer, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;
        allocated = MALLOC_SIZEOF_SAFE(*buffer);

        r = sym_LZ4_decompress_safe_partial(
                        (char*)src + 8,
                        *buffer,
                        src_size - 8,
                        prefix_len + 1,
                        allocated);

        /* One lz4 < 1.8.3, we might get "failure" (r < 0), or "success" where just a part of the buffer is
         * decompressed. But if we get a smaller amount of bytes than requested, we don't know whether there
         * isn't enough data to fill the requested size or whether we just got a partial answer.
         */
        if (r < 0 || (size_t) r < prefix_len + 1) {
                size_t size;

                if (sym_LZ4_versionNumber() >= 10803)
                        /* We trust that the newer lz4 decompresses the number of bytes we
                         * requested if available in the compressed string. */
                        return 0;

                if (r > 0)
                        /* Compare what we have first, in case of mismatch we can
                         * shortcut the full comparison. */
                        if (memcmp(*buffer, prefix, r) != 0)
                                return 0;

                /* Before version 1.8.3, lz4 always tries to decode full a "sequence",
                 * so in pathological cases might need to decompress the full field. */
                r = decompress_blob_lz4(src, src_size, buffer, &size, 0);
                if (r < 0)
                        return r;

                if (size < prefix_len + 1)
                        return 0;
        }

        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                ((const uint8_t*) *buffer)[prefix_len] == extra;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_startswith_zstd(
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(prefix);

#if HAVE_ZSTD
        int r;

        r = dlopen_zstd(LOG_DEBUG);
        if (r < 0)
                return r;

        uint64_t size = sym_ZSTD_getFrameContentSize(src, src_size);
        if (IN_SET(size, ZSTD_CONTENTSIZE_ERROR, ZSTD_CONTENTSIZE_UNKNOWN))
                return -EBADMSG;

        if (size < prefix_len + 1)
                return 0; /* Decompressed text too short to match the prefix and extra */

        _cleanup_(ZSTD_freeDCtxp) ZSTD_DCtx *dctx = sym_ZSTD_createDCtx();
        if (!dctx)
                return -ENOMEM;

        if (!(greedy_realloc(buffer, MAX(sym_ZSTD_DStreamOutSize(), prefix_len + 1), 1)))
                return -ENOMEM;

        ZSTD_inBuffer input = {
                .src = src,
                .size = src_size,
        };
        ZSTD_outBuffer output = {
                .dst = *buffer,
                .size = MALLOC_SIZEOF_SAFE(*buffer),
        };
        size_t k;

        k = sym_ZSTD_decompressStream(dctx, &output, &input);
        if (sym_ZSTD_isError(k))
                return log_debug_errno(zstd_ret_to_errno(k), "ZSTD decoder failed: %s", sym_ZSTD_getErrorName(k));
        if (output.pos < prefix_len + 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "ZSTD decoded less data than indicated, probably corrupted stream.");

        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                ((const uint8_t*) *buffer)[prefix_len] == extra;
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_startswith_gzip(
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(prefix);

#if HAVE_ZLIB
        int r;

        r = dlopen_zlib(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;

        _cleanup_(inflateEnd_wrapper) z_stream s = {};

        r = sym_inflateInit2_(&s, /* windowBits= */ ZLIB_WBITS_GZIP, ZLIB_VERSION, (int) sizeof(s));
        if (r != Z_OK)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        size_t allocated = MALLOC_SIZEOF_SAFE(*buffer);

        s.next_in = (void*) src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = MIN(allocated, (size_t) UINT_MAX);

        for (;;) {
                r = sym_inflate(&s, Z_FINISH);

                if (!IN_SET(r, Z_OK, Z_STREAM_END, Z_BUF_ERROR))
                        return -EBADMSG;

                if (allocated - s.avail_out >= prefix_len + 1)
                        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                                ((const uint8_t*) *buffer)[prefix_len] == extra;

                if (r == Z_STREAM_END)
                        return 0;

                size_t used = allocated - s.avail_out;

                if (!(greedy_realloc(buffer, allocated * 2, 1)))
                        return -ENOMEM;

                allocated = MALLOC_SIZEOF_SAFE(*buffer);
                s.avail_out = MIN(allocated - used, (size_t) UINT_MAX);
                s.next_out = *(uint8_t**)buffer + used;
        }
#else
        return -EPROTONOSUPPORT;
#endif
}

static int decompress_startswith_bzip2(
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(prefix);

#if HAVE_BZIP2
        int r;

        r = dlopen_bzip2(LOG_DEBUG);
        if (r < 0)
                return r;

        if (src_size > UINT_MAX)
                return -EFBIG;

        _cleanup_(BZ2_bzDecompressEnd_wrapper) bz_stream s = {};

        r = sym_BZ2_bzDecompressInit(&s, /* verbosity= */ 0, /* small= */ 0);
        if (r != BZ_OK)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        size_t allocated = MALLOC_SIZEOF_SAFE(*buffer);

        s.next_in = (char*) src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = MIN(allocated, (size_t) UINT_MAX);

        for (;;) {
                r = sym_BZ2_bzDecompress(&s);

                if (!IN_SET(r, BZ_OK, BZ_STREAM_END))
                        return -EBADMSG;

                if (allocated - s.avail_out >= prefix_len + 1)
                        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                                ((const uint8_t*) *buffer)[prefix_len] == extra;

                if (r == BZ_STREAM_END)
                        return 0;

                size_t used = allocated - s.avail_out;

                if (!(greedy_realloc(buffer, allocated * 2, 1)))
                        return -ENOMEM;

                allocated = MALLOC_SIZEOF_SAFE(*buffer);
                s.avail_out = MIN(allocated - used, (size_t) UINT_MAX);
                s.next_out = (char*) *buffer + used;
        }
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_startswith(
                Compression compression,
                const void *src, uint64_t src_size,
                void **buffer,
                const void *prefix, size_t prefix_len,
                uint8_t extra) {

        switch (compression) {
        case COMPRESSION_XZ:
                return decompress_startswith_xz(src, src_size, buffer, prefix, prefix_len, extra);
        case COMPRESSION_LZ4:
                return decompress_startswith_lz4(src, src_size, buffer, prefix, prefix_len, extra);
        case COMPRESSION_ZSTD:
                return decompress_startswith_zstd(src, src_size, buffer, prefix, prefix_len, extra);
        case COMPRESSION_GZIP:
                return decompress_startswith_gzip(src, src_size, buffer, prefix, prefix_len, extra);
        case COMPRESSION_BZIP2:
                return decompress_startswith_bzip2(src, src_size, buffer, prefix, prefix_len, extra);
        default:
                return -EOPNOTSUPP;
        }
}

int compress_stream(
                Compression type,
                int fdf, int fdt,
                uint64_t max_bytes,
                uint64_t *ret_uncompressed_size) {

        _cleanup_(compressor_freep) Compressor *c = NULL;
        _cleanup_free_ void *buf = NULL;
        _cleanup_free_ uint8_t *input = NULL;
        size_t buf_size = 0, buf_alloc = 0;
        uint64_t total_in = 0, total_out = 0;
        int r;

        assert(fdf >= 0);
        assert(fdt >= 0);

        r = compressor_new(&c, type);
        if (r < 0)
                return r;

        input = new(uint8_t, COMPRESS_PIPE_BUFFER_SIZE);
        if (!input)
                return -ENOMEM;

        for (;;) {
                size_t m = COMPRESS_PIPE_BUFFER_SIZE;
                ssize_t n;

                if (max_bytes != UINT64_MAX && (uint64_t) m > max_bytes)
                        m = (size_t) max_bytes;

                n = read(fdf, input, m);
                if (n < 0)
                        return -errno;

                if (n == 0) {
                        r = compressor_finish(c, &buf, &buf_size, &buf_alloc);
                        if (r < 0)
                                return r;

                        if (buf_size > 0) {
                                r = loop_write(fdt, buf, buf_size);
                                if (r < 0)
                                        return r;
                                total_out += buf_size;
                        }
                        break;
                }

                total_in += n;
                if (max_bytes != UINT64_MAX) {
                        assert(max_bytes >= (uint64_t) n);
                        max_bytes -= n;
                }

                r = compressor_start(c, input, n, &buf, &buf_size, &buf_alloc);
                if (r < 0)
                        return r;

                if (buf_size > 0) {
                        r = loop_write(fdt, buf, buf_size);
                        if (r < 0)
                                return r;
                        total_out += buf_size;
                }
        }

        if (ret_uncompressed_size)
                *ret_uncompressed_size = total_in;

        if (total_in == 0)
                log_debug("%s compression finished (no input data)", compression_to_string(type));
        else
                log_debug("%s compression finished (%" PRIu64 " -> %" PRIu64 " bytes, %.1f%%)",
                          compression_to_string(type), total_in, total_out, (double) total_out / total_in * 100);

        return 0;
}

/* Determine whether sparse writes should be used for this fd. Sparse writes are only safe on
 * regular files without O_APPEND (O_APPEND ignores lseek position, which would collapse holes). */
static int should_sparse(int fd) {
        struct stat st;

        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        int flags = fcntl(fd, F_GETFL);
        if (flags < 0)
                return -errno;

        return S_ISREG(st.st_mode) && !FLAGS_SET(flags, O_APPEND);
}

/* After sparse decompression, set the file size to the current position to account for
 * trailing holes that sparse_write() created via lseek but never extended the file size for. */
static int finalize_sparse(int fd) {
        off_t pos;

        assert(fd >= 0);

        pos = lseek(fd, 0, SEEK_CUR);
        if (pos < 0)
                return -errno;

        if (ftruncate(fd, pos) < 0)
                return -errno;

        return 0;
}

/* Common helper for decompress_stream_*() wrappers */

struct decompress_stream_userdata {
        int fd;
        uint64_t max_bytes;
        uint64_t total_out;
        bool sparse;
};

static int decompress_stream_write_callback(const void *data, size_t size, void *userdata) {
        struct decompress_stream_userdata *u = ASSERT_PTR(userdata);

        if (u->max_bytes != UINT64_MAX) {
                if (u->max_bytes < size)
                        return -EFBIG;
                u->max_bytes -= size;
        }

        u->total_out += size;

        if (u->sparse) {
                /* Note: sparse_write() does not retry on EINTR and converts short writes to -EIO.
                 * This is fine here since sparse mode is only used on regular files, where short
                 * writes and EINTR are not expected in practice. */
                ssize_t k = sparse_write(u->fd, data, size, 64);
                if (k < 0)
                        return (int) k;
                return 0;
        }

        return loop_write(u->fd, data, size);
}

static int decompressor_new(Decompressor **ret, Compression type) {
#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        int r;
#endif

        assert(ret);

        _cleanup_(compressor_freep) Decompressor *c = new0(Decompressor, 1);
        if (!c)
                return -ENOMEM;

        c->type = _COMPRESSION_INVALID;

        switch (type) {

#if HAVE_XZ
        case COMPRESSION_XZ:
                r = dlopen_xz(LOG_DEBUG);
                if (r < 0)
                        return r;

                if (sym_lzma_stream_decoder(&c->xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED) != LZMA_OK)
                        return -EIO;
                break;
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                r = dlopen_lz4(LOG_DEBUG);
                if (r < 0)
                        return r;

                size_t rc = sym_LZ4F_createDecompressionContext(&c->d_lz4, LZ4F_VERSION);
                if (sym_LZ4F_isError(rc))
                        return -ENOMEM;

                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD:
                r = dlopen_zstd(LOG_DEBUG);
                if (r < 0)
                        return r;

                c->d_zstd = sym_ZSTD_createDCtx();
                if (!c->d_zstd)
                        return -ENOMEM;
                break;
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                r = dlopen_zlib(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_inflateInit2_(&c->gzip, /* windowBits= */ ZLIB_WBITS_GZIP, ZLIB_VERSION, (int) sizeof(c->gzip));
                if (r != Z_OK)
                        return -EIO;
                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                r = dlopen_bzip2(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_BZ2_bzDecompressInit(&c->bzip2, /* verbosity= */ 0, /* small= */ 0);
                if (r != BZ_OK)
                        return -EIO;
                break;
#endif

        default:
                return -EOPNOTSUPP;
        }

        c->type = type;
        c->encoding = false;
        *ret = TAKE_PTR(c);
        return 0;
}

int decompress_stream(
                Compression type,
                int fdf, int fdt,
                uint64_t max_bytes) {

        _cleanup_(compressor_freep) Decompressor *c = NULL;
        _cleanup_free_ uint8_t *buf = NULL;
        uint64_t total_in = 0;
        int r;

        assert(fdf >= 0);
        assert(fdt >= 0);

        r = decompressor_new(&c, type);
        if (r < 0)
                return r;

        struct decompress_stream_userdata userdata = {
                .fd = fdt,
                .max_bytes = max_bytes,
                .sparse = should_sparse(fdt) > 0,
        };

        buf = new(uint8_t, COMPRESS_PIPE_BUFFER_SIZE);
        if (!buf)
                return -ENOMEM;

        for (;;) {
                ssize_t n;

                n = read(fdf, buf, COMPRESS_PIPE_BUFFER_SIZE);
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break;

                total_in += n;

                r = decompressor_push(c, buf, n, decompress_stream_write_callback, &userdata);
                if (r < 0)
                        return r;
        }

        if (total_in == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "%s decompression failed: no data read",
                                       compression_to_string(type));

        if (userdata.sparse) {
                r = finalize_sparse(fdt);
                if (r < 0)
                        return r;
        }

        log_debug("%s decompression finished (%" PRIu64 " -> %" PRIu64 " bytes, %.1f%%)",
                  compression_to_string(type), total_in, userdata.total_out,
                  (double) userdata.total_out / total_in * 100);

        return 0;
}

int decompress_stream_by_filename(const char *filename, int fdf, int fdt, uint64_t max_bytes) {
        Compression c = compression_from_filename(filename);
        if (c == COMPRESSION_NONE)
                return -EPROTONOSUPPORT;

        return decompress_stream(c, fdf, fdt, max_bytes);
}

/* Push-based streaming compression/decompression context API */

Compressor* compressor_free(Compressor *c) {
        if (!c)
                return NULL;

        switch (c->type) {

#if HAVE_XZ
        case COMPRESSION_XZ:
                sym_lzma_end(&c->xz);
                break;
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4:
                if (c->encoding) {
                        sym_LZ4F_freeCompressionContext(c->c_lz4);
                        c->c_lz4 = NULL;
                        c->lz4_header = mfree(c->lz4_header);
                } else {
                        sym_LZ4F_freeDecompressionContext(c->d_lz4);
                        c->d_lz4 = NULL;
                }
                break;
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD:
                if (c->encoding) {
                        sym_ZSTD_freeCCtx(c->c_zstd);
                        c->c_zstd = NULL;
                } else {
                        sym_ZSTD_freeDCtx(c->d_zstd);
                        c->d_zstd = NULL;
                }
                break;
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                if (c->encoding)
                        sym_deflateEnd(&c->gzip);
                else
                        sym_inflateEnd(&c->gzip);
                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                if (c->encoding)
                        sym_BZ2_bzCompressEnd(&c->bzip2);
                else
                        sym_BZ2_bzDecompressEnd(&c->bzip2);
                break;
#endif

        default:
                break;
        }

        return mfree(c);
}

Compression compressor_type(const Compressor *c) {
        return c ? c->type : _COMPRESSION_INVALID;
}

int decompressor_detect(Decompressor **ret, const void *data, size_t size) {
#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        int r;
#endif

        assert(ret);

        if (*ret)
                return 1;

        if (size < COMPRESSION_MAGIC_BYTES_MAX)
                return 0;

        assert(data);

        Compression type = compression_detect_from_magic(data);

        _cleanup_(compressor_freep) Decompressor *c = new0(Decompressor, 1);
        if (!c)
                return -ENOMEM;

        switch (type) {

#if HAVE_XZ
        case COMPRESSION_XZ: {
                r = dlopen_xz(LOG_DEBUG);
                if (r < 0)
                        return r;

                lzma_ret xzr = sym_lzma_stream_decoder(&c->xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED);
                if (xzr != LZMA_OK)
                        return -EIO;

                break;
        }
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                r = dlopen_lz4(LOG_DEBUG);
                if (r < 0)
                        return r;

                size_t rc = sym_LZ4F_createDecompressionContext(&c->d_lz4, LZ4F_VERSION);
                if (sym_LZ4F_isError(rc))
                        return -ENOMEM;

                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD: {
                r = dlopen_zstd(LOG_DEBUG);
                if (r < 0)
                        return r;

                c->d_zstd = sym_ZSTD_createDCtx();
                if (!c->d_zstd)
                        return -ENOMEM;

                break;
        }
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP: {
                r = dlopen_zlib(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_inflateInit2_(&c->gzip, /* windowBits= */ ZLIB_WBITS_GZIP, ZLIB_VERSION, (int) sizeof(c->gzip));
                if (r != Z_OK)
                        return -EIO;

                break;
        }
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2: {
                r = dlopen_bzip2(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_BZ2_bzDecompressInit(&c->bzip2, /* verbosity= */ 0, /* small= */ 0);
                if (r != BZ_OK)
                        return -EIO;

                break;
        }
#endif

        default:
                if (type != _COMPRESSION_INVALID)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Detected %s compression, but support is not compiled in.",
                                               compression_to_string(type));
                type = COMPRESSION_NONE;
                break;
        }

        c->type = type;
        c->encoding = false;

        log_debug("Detected compression type: %s", compression_to_string(c->type));
        *ret = TAKE_PTR(c);
        return 1;
}

int decompressor_force_off(Decompressor **ret) {
        assert(ret);

        *ret = compressor_free(*ret);

        Decompressor *c = new0(Decompressor, 1);
        if (!c)
                return -ENOMEM;

        c->type = COMPRESSION_NONE;
        c->encoding = false;
        *ret = c;
        return 0;
}

int decompressor_push(Decompressor *c, const void *data, size_t size, DecompressorCallback callback, void *userdata) {
#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        _cleanup_free_ uint8_t *buffer = NULL;
#endif
        int r;

        assert(c);
        assert(callback);

        if (c->encoding)
                return -EINVAL;

        if (size == 0)
                return 1;

        assert(data);

#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        if (c->type != COMPRESSION_NONE) {
                buffer = new(uint8_t, COMPRESS_PIPE_BUFFER_SIZE);
                if (!buffer)
                        return -ENOMEM;
        }
#endif

        switch (c->type) {

        case COMPRESSION_NONE:
                r = callback(data, size, userdata);
                if (r < 0)
                        return r;

                break;

#if HAVE_XZ
        case COMPRESSION_XZ:
                c->xz.next_in = data;
                c->xz.avail_in = size;

                while (c->xz.avail_in > 0) {
                        c->xz.next_out = buffer;
                        c->xz.avail_out = COMPRESS_PIPE_BUFFER_SIZE;

                        lzma_ret lzr = sym_lzma_code(&c->xz, LZMA_RUN);
                        if (!IN_SET(lzr, LZMA_OK, LZMA_STREAM_END))
                                return -EBADMSG;

                        if (c->xz.avail_out < COMPRESS_PIPE_BUFFER_SIZE) {
                                r = callback(buffer, COMPRESS_PIPE_BUFFER_SIZE - c->xz.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                const uint8_t *src = data;
                size_t src_remaining = size;

                while (src_remaining > 0) {
                        size_t produced = COMPRESS_PIPE_BUFFER_SIZE;
                        size_t consumed = src_remaining;

                        size_t rc = sym_LZ4F_decompress(c->d_lz4, buffer, &produced, src, &consumed, NULL);
                        if (sym_LZ4F_isError(rc))
                                return -EBADMSG;

                        if (consumed == 0 && produced == 0)
                                break; /* No progress possible with current input */

                        src += consumed;
                        src_remaining -= consumed;

                        if (produced > 0) {
                                r = callback(buffer, produced, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD: {
                ZSTD_inBuffer input = {
                        .src =  (void*) data,
                        .size = size,
                };

                while (input.pos < input.size) {
                        ZSTD_outBuffer output = {
                                .dst = buffer,
                                .size = COMPRESS_PIPE_BUFFER_SIZE,
                        };

                        size_t res = sym_ZSTD_decompressStream(c->d_zstd, &output, &input);
                        if (sym_ZSTD_isError(res))
                                return -EBADMSG;

                        if (output.pos > 0) {
                                r = callback(output.dst, output.pos, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;
        }
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                if (size > UINT_MAX)
                        return -EFBIG;

                c->gzip.next_in = (void*) data;
                c->gzip.avail_in = size;

                while (c->gzip.avail_in > 0) {
                        c->gzip.next_out = buffer;
                        c->gzip.avail_out = COMPRESS_PIPE_BUFFER_SIZE;

                        int zr = sym_inflate(&c->gzip, Z_NO_FLUSH);
                        if (!IN_SET(zr, Z_OK, Z_STREAM_END))
                                return -EBADMSG;

                        if (c->gzip.avail_out < COMPRESS_PIPE_BUFFER_SIZE) {
                                r = callback(buffer, COMPRESS_PIPE_BUFFER_SIZE - c->gzip.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }

                        if (zr == Z_STREAM_END)
                                break;
                }

                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                if (size > UINT_MAX)
                        return -EFBIG;

                c->bzip2.next_in = (char*) data;
                c->bzip2.avail_in = size;

                while (c->bzip2.avail_in > 0) {
                        c->bzip2.next_out = (char*) buffer;
                        c->bzip2.avail_out = COMPRESS_PIPE_BUFFER_SIZE;

                        int bzr = sym_BZ2_bzDecompress(&c->bzip2);
                        if (!IN_SET(bzr, BZ_OK, BZ_STREAM_END))
                                return -EBADMSG;

                        if (c->bzip2.avail_out < COMPRESS_PIPE_BUFFER_SIZE) {
                                r = callback(buffer, COMPRESS_PIPE_BUFFER_SIZE - c->bzip2.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }

                        if (bzr == BZ_STREAM_END)
                                break;
                }

                break;
#endif

        default:
                assert_not_reached();
        }

        return 1;
}

int compressor_new(Compressor **ret, Compression type) {
#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        int r;
#endif

        assert(ret);

        _cleanup_(compressor_freep) Compressor *c = new0(Compressor, 1);
        if (!c)
                return -ENOMEM;

        c->type = _COMPRESSION_INVALID;
        /* Set encoding early so that compressor_freep calls the correct cleanup (compression vs
         * decompression) if any operation in the switch fails after setting c->type. This is safe
         * because _COMPRESSION_INVALID hits the default: break case regardless of the encoding flag. */
        c->encoding = true;

        switch (type) {

#if HAVE_XZ
        case COMPRESSION_XZ: {
                r = dlopen_xz(LOG_DEBUG);
                if (r < 0)
                        return r;

                lzma_ret xzr = sym_lzma_easy_encoder(&c->xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
                if (xzr != LZMA_OK)
                        return -EIO;

                c->type = COMPRESSION_XZ;
                break;
        }
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                r = dlopen_lz4(LOG_DEBUG);
                if (r < 0)
                        return r;

                size_t rc = sym_LZ4F_createCompressionContext(&c->c_lz4, LZ4F_VERSION);
                if (sym_LZ4F_isError(rc))
                        return -ENOMEM;

                c->type = COMPRESSION_LZ4;

                /* Generate the frame header and stash it for the first compressor_start call */
                size_t header_bound = sym_LZ4F_compressBound(0, &lz4_preferences);
                c->lz4_header = malloc(header_bound);
                if (!c->lz4_header)
                        return -ENOMEM;

                c->lz4_header_size = sym_LZ4F_compressBegin(c->c_lz4, c->lz4_header, header_bound, &lz4_preferences);
                if (sym_LZ4F_isError(c->lz4_header_size))
                        return -EINVAL;

                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD:
                r = dlopen_zstd(LOG_DEBUG);
                if (r < 0)
                        return r;

                c->c_zstd = sym_ZSTD_createCCtx();
                if (!c->c_zstd)
                        return -ENOMEM;

                c->type = COMPRESSION_ZSTD;

                size_t z = sym_ZSTD_CCtx_setParameter(c->c_zstd, ZSTD_c_compressionLevel, ZSTD_CLEVEL_DEFAULT);
                if (sym_ZSTD_isError(z))
                        return -EIO;

                z = sym_ZSTD_CCtx_setParameter(c->c_zstd, ZSTD_c_checksumFlag, /* enable= */ 1);
                if (sym_ZSTD_isError(z))
                        log_debug("Failed to enable ZSTD checksum, ignoring: %s", sym_ZSTD_getErrorName(z));

                break;
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                r = dlopen_zlib(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_deflateInit2_(&c->gzip,
                                      Z_DEFAULT_COMPRESSION,
                                      /* method= */ Z_DEFLATED,
                                      /* windowBits= */ ZLIB_WBITS_GZIP,
                                      /* memLevel= */ 8,
                                      /* strategy= */ Z_DEFAULT_STRATEGY,
                                      ZLIB_VERSION, (int) sizeof(c->gzip));
                if (r != Z_OK)
                        return -EIO;

                c->type = COMPRESSION_GZIP;
                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                r = dlopen_bzip2(LOG_DEBUG);
                if (r < 0)
                        return r;

                r = sym_BZ2_bzCompressInit(&c->bzip2, /* blockSize100k= */ 9, /* verbosity= */ 0, /* workFactor= */ 0);
                if (r != BZ_OK)
                        return -EIO;

                c->type = COMPRESSION_BZIP2;
                break;
#endif

        case COMPRESSION_NONE:
                c->type = COMPRESSION_NONE;
                break;

        default:
                return -EOPNOTSUPP;
        }

        *ret = TAKE_PTR(c);
        return 0;
}

#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
static int enlarge_buffer(void **buffer, size_t *buffer_size, size_t *buffer_allocated, size_t need) {
        assert(buffer);
        assert(buffer_size);
        assert(buffer_allocated);

        need = MAX3(need, *buffer_size + 1, (size_t) COMPRESS_PIPE_BUFFER_SIZE);
        if (*buffer_allocated >= need)
                return 0;

        if (!greedy_realloc(buffer, need, 1))
                return -ENOMEM;

        *buffer_allocated = MALLOC_SIZEOF_SAFE(*buffer);
        return 1;
}
#endif

int compressor_start(
                Compressor *c,
                const void *data,
                size_t size,
                void **buffer,
                size_t *buffer_size,
                size_t *buffer_allocated) {

#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        int r;
#endif

        assert(c);
        assert(buffer);
        assert(buffer_size);
        assert(buffer_allocated);

        if (!c->encoding)
                return -EINVAL;

        if (size == 0)
                return 0;

        assert(data);

        *buffer_size = 0;

        switch (c->type) {

#if HAVE_XZ
        case COMPRESSION_XZ:

                c->xz.next_in = data;
                c->xz.avail_in = size;

                while (c->xz.avail_in > 0) {
                        lzma_ret lzr;

                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        c->xz.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->xz.avail_out = *buffer_allocated - *buffer_size;

                        lzr = sym_lzma_code(&c->xz, LZMA_RUN);
                        if (lzr != LZMA_OK)
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->xz.avail_out;
                }

                break;
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                /* Prepend any stashed frame header from compressor_new */
                if (c->lz4_header_size > 0) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, c->lz4_header_size);
                        if (r < 0)
                                return r;

                        memcpy(*buffer, c->lz4_header, c->lz4_header_size);
                        *buffer_size = c->lz4_header_size;
                        c->lz4_header = mfree(c->lz4_header);
                        c->lz4_header_size = 0;
                }

                size_t bound = sym_LZ4F_compressBound(size, &lz4_preferences);
                r = enlarge_buffer(buffer, buffer_size, buffer_allocated, *buffer_size + bound);
                if (r < 0)
                        return r;

                size_t n = sym_LZ4F_compressUpdate(c->c_lz4,
                                                   (uint8_t*) *buffer + *buffer_size,
                                                   *buffer_allocated - *buffer_size,
                                                   data, size, NULL);
                if (sym_LZ4F_isError(n))
                        return -EIO;

                *buffer_size += n;
                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD: {
                ZSTD_inBuffer input = {
                        .src = data,
                        .size = size,
                };

                while (input.pos < input.size) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        ZSTD_outBuffer output = {
                                .dst = ((uint8_t *) *buffer + *buffer_size),
                                .size = *buffer_allocated - *buffer_size,
                        };

                        size_t res = sym_ZSTD_compressStream2(c->c_zstd, &output, &input, ZSTD_e_continue);
                        if (sym_ZSTD_isError(res))
                                return -EIO;

                        *buffer_size += output.pos;
                }

                break;
        }
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                if (size > UINT_MAX)
                        return -EFBIG;

                c->gzip.next_in = (void*) data;
                c->gzip.avail_in = size;

                while (c->gzip.avail_in > 0) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        size_t avail = MIN(*buffer_allocated - *buffer_size, (size_t) UINT_MAX);
                        c->gzip.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->gzip.avail_out = avail;

                        r = sym_deflate(&c->gzip, Z_NO_FLUSH);
                        if (r != Z_OK)
                                return -EIO;

                        *buffer_size += avail - c->gzip.avail_out;
                }

                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                if (size > UINT_MAX)
                        return -EFBIG;

                c->bzip2.next_in = (void*) data;
                c->bzip2.avail_in = size;

                while (c->bzip2.avail_in > 0) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        size_t avail = MIN(*buffer_allocated - *buffer_size, (size_t) UINT_MAX);
                        c->bzip2.next_out = (void*) ((uint8_t*) *buffer + *buffer_size);
                        c->bzip2.avail_out = avail;

                        r = sym_BZ2_bzCompress(&c->bzip2, BZ_RUN);
                        if (r != BZ_RUN_OK)
                                return -EIO;

                        *buffer_size += avail - c->bzip2.avail_out;
                }

                break;
#endif

        case COMPRESSION_NONE:

                if (*buffer_allocated < size) {
                        void *p;

                        p = realloc(*buffer, size);
                        if (!p)
                                return -ENOMEM;

                        *buffer = p;
                        *buffer_allocated = size;
                }

                memcpy(*buffer, data, size);
                *buffer_size = size;
                break;

        default:
                return -EOPNOTSUPP;
        }

        return 0;
}

int compressor_finish(Compressor *c, void **buffer, size_t *buffer_size, size_t *buffer_allocated) {
#if HAVE_XZ || HAVE_LZ4 || HAVE_ZSTD || HAVE_ZLIB || HAVE_BZIP2
        int r;
#endif

        assert(c);
        assert(buffer);
        assert(buffer_size);
        assert(buffer_allocated);

        if (!c->encoding)
                return -EINVAL;

        *buffer_size = 0;

        switch (c->type) {

#if HAVE_XZ
        case COMPRESSION_XZ: {
                lzma_ret lzr;

                c->xz.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        c->xz.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->xz.avail_out = *buffer_allocated - *buffer_size;

                        lzr = sym_lzma_code(&c->xz, LZMA_FINISH);
                        if (!IN_SET(lzr, LZMA_OK, LZMA_STREAM_END))
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->xz.avail_out;
                } while (lzr != LZMA_STREAM_END);

                break;
        }
#endif

#if HAVE_LZ4
        case COMPRESSION_LZ4: {
                size_t bound = sym_LZ4F_compressBound(0, &lz4_preferences);
                r = enlarge_buffer(buffer, buffer_size, buffer_allocated, bound);
                if (r < 0)
                        return r;

                size_t n = sym_LZ4F_compressEnd(c->c_lz4, *buffer, *buffer_allocated, NULL);
                if (sym_LZ4F_isError(n))
                        return -EIO;

                *buffer_size = n;
                break;
        }
#endif

#if HAVE_ZSTD
        case COMPRESSION_ZSTD: {
                ZSTD_inBuffer input = {};
                size_t res;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        ZSTD_outBuffer output = {
                                .dst = ((uint8_t *) *buffer + *buffer_size),
                                .size = *buffer_allocated - *buffer_size,
                        };

                        res = sym_ZSTD_compressStream2(c->c_zstd, &output, &input, ZSTD_e_end);
                        if (sym_ZSTD_isError(res))
                                return -EIO;

                        *buffer_size += output.pos;
                } while (res != 0);

                break;
        }
#endif

#if HAVE_ZLIB
        case COMPRESSION_GZIP:
                c->gzip.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        size_t avail = MIN(*buffer_allocated - *buffer_size, (size_t) UINT_MAX);
                        c->gzip.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->gzip.avail_out = avail;

                        r = sym_deflate(&c->gzip, Z_FINISH);
                        if (!IN_SET(r, Z_OK, Z_STREAM_END))
                                return -EIO;

                        *buffer_size += avail - c->gzip.avail_out;
                } while (r != Z_STREAM_END);

                break;
#endif

#if HAVE_BZIP2
        case COMPRESSION_BZIP2:
                c->bzip2.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated, /* need= */ 0);
                        if (r < 0)
                                return r;

                        size_t avail = MIN(*buffer_allocated - *buffer_size, (size_t) UINT_MAX);
                        c->bzip2.next_out = (void*) ((uint8_t*) *buffer + *buffer_size);
                        c->bzip2.avail_out = avail;

                        r = sym_BZ2_bzCompress(&c->bzip2, BZ_FINISH);
                        if (!IN_SET(r, BZ_FINISH_OK, BZ_STREAM_END))
                                return -EIO;

                        *buffer_size += avail - c->bzip2.avail_out;
                } while (r != BZ_STREAM_END);

                break;
#endif

        case COMPRESSION_NONE:
                break;

        default:
                return -EOPNOTSUPP;
        }

        return 0;
}
