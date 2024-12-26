/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <inttypes.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if HAVE_XZ
#include <lzma.h>
#endif

#if HAVE_ZSTD
#include <zstd.h>
#include <zstd_errors.h>
#endif

#include "alloc-util.h"
#include "bitfield.h"
#include "compress.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "macro.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "string-util.h"
#include "unaligned.h"

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
DLSYM_PROTOTYPE(LZ4_compress_default) = NULL;
DLSYM_PROTOTYPE(LZ4_decompress_safe) = NULL;
DLSYM_PROTOTYPE(LZ4_decompress_safe_partial) = NULL;
DLSYM_PROTOTYPE(LZ4_versionNumber) = NULL;

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(LZ4F_compressionContext_t, sym_LZ4F_freeCompressionContext, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(LZ4F_decompressionContext_t, sym_LZ4F_freeDecompressionContext, NULL);
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

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ZSTD_CCtx*, sym_ZSTD_freeCCtx, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(ZSTD_DCtx*, sym_ZSTD_freeDCtx, NULL);

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

#if HAVE_XZ
static void *lzma_dl = NULL;

static DLSYM_PROTOTYPE(lzma_code) = NULL;
static DLSYM_PROTOTYPE(lzma_easy_encoder) = NULL;
static DLSYM_PROTOTYPE(lzma_end) = NULL;
static DLSYM_PROTOTYPE(lzma_stream_buffer_encode) = NULL;
static DLSYM_PROTOTYPE(lzma_stream_decoder) = NULL;

/* We can't just do _cleanup_(sym_lzma_end) because a compiler bug makes
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

#define ALIGN_8(l) ALIGN_TO(l, sizeof(size_t))

static const char* const compression_table[_COMPRESSION_MAX] = {
        [COMPRESSION_NONE] = "NONE",
        [COMPRESSION_XZ]   = "XZ",
        [COMPRESSION_LZ4]  = "LZ4",
        [COMPRESSION_ZSTD] = "ZSTD",
};

DEFINE_STRING_TABLE_LOOKUP(compression, Compression);

bool compression_supported(Compression c) {
        static const unsigned supported =
                (1U << COMPRESSION_NONE) |
                (1U << COMPRESSION_XZ) * HAVE_XZ |
                (1U << COMPRESSION_LZ4) * HAVE_LZ4 |
                (1U << COMPRESSION_ZSTD) * HAVE_ZSTD;

        assert(c >= 0);
        assert(c < _COMPRESSION_MAX);

        return BIT_SET(supported, c);
}

#if HAVE_XZ
int dlopen_lzma(void) {
        ELF_NOTE_DLOPEN("lzma",
                        "Support lzma compression in journal and coredump files",
                        COMPRESSION_PRIORITY_XZ,
                        "liblzma.so.5");

        return dlopen_many_sym_or_warn(
                        &lzma_dl,
                        "liblzma.so.5", LOG_DEBUG,
                        DLSYM_ARG(lzma_code),
                        DLSYM_ARG(lzma_easy_encoder),
                        DLSYM_ARG(lzma_end),
                        DLSYM_ARG(lzma_stream_buffer_encode),
                        DLSYM_ARG(lzma_stream_decoder));
}
#endif

int compress_blob_xz(const void *src, uint64_t src_size,
                     void *dst, size_t dst_alloc_size, size_t *dst_size) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_XZ
        static const lzma_options_lzma opt = {
                1u << 20u, NULL, 0, LZMA_LC_DEFAULT, LZMA_LP_DEFAULT,
                LZMA_PB_DEFAULT, LZMA_MODE_FAST, 128, LZMA_MF_HC3, 4
        };
        static const lzma_filter filters[] = {
                { LZMA_FILTER_LZMA2, (lzma_options_lzma*) &opt },
                { LZMA_VLI_UNKNOWN, NULL }
        };
        lzma_ret ret;
        size_t out_pos = 0;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 80)
                return -ENOBUFS;

        ret = sym_lzma_stream_buffer_encode((lzma_filter*) filters, LZMA_CHECK_NONE, NULL,
                                        src, src_size, dst, &out_pos, dst_alloc_size);
        if (ret != LZMA_OK)
                return -ENOBUFS;

        *dst_size = out_pos;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

#if HAVE_LZ4
int dlopen_lz4(void) {
        ELF_NOTE_DLOPEN("lz4",
                        "Support lz4 compression in journal and coredump files",
                        COMPRESSION_PRIORITY_LZ4,
                        "liblz4.so.1");

        return dlopen_many_sym_or_warn(
                        &lz4_dl,
                        "liblz4.so.1", LOG_DEBUG,
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
                        DLSYM_ARG(LZ4_decompress_safe),
                        DLSYM_ARG(LZ4_decompress_safe_partial),
                        DLSYM_ARG(LZ4_versionNumber));
}
#endif

int compress_blob_lz4(const void *src, uint64_t src_size,
                      void *dst, size_t dst_alloc_size, size_t *dst_size) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_LZ4
        int r;

        r = dlopen_lz4();
        if (r < 0)
                return r;
        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 9)
                return -ENOBUFS;

        r = sym_LZ4_compress_default(src, (char*)dst + 8, src_size, (int) dst_alloc_size - 8);
        if (r <= 0)
                return -ENOBUFS;

        unaligned_write_le64(dst, src_size);
        *dst_size = r + 8;

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

#if HAVE_ZSTD
int dlopen_zstd(void) {
        ELF_NOTE_DLOPEN("zstd",
                        "Support zstd compression in journal and coredump files",
                        COMPRESSION_PRIORITY_ZSTD,
                        "libzstd.so.1");

        return dlopen_many_sym_or_warn(
                        &zstd_dl,
                        "libzstd.so.1", LOG_DEBUG,
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
}
#endif

int compress_blob_zstd(
                const void *src, uint64_t src_size,
                void *dst, size_t dst_alloc_size, size_t *dst_size) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

#if HAVE_ZSTD
        size_t k;
        int r;

        r = dlopen_zstd();
        if (r < 0)
                return r;

        k = sym_ZSTD_compress(dst, dst_alloc_size, src, src_size, 0);
        if (sym_ZSTD_isError(k))
                return zstd_ret_to_errno(k);

        *dst_size = k;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob_xz(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t* dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_XZ
        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        size_t space;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        ret = sym_lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return -ENOMEM;

        space = MIN(src_size * 2, dst_max ?: SIZE_MAX);
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
                else if (ret != LZMA_OK)
                        return -ENOMEM;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                else if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
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

int decompress_blob_lz4(
                const void *src,
                uint64_t src_size,
                void **dst,
                size_t* dst_size,
                size_t dst_max) {

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

#if HAVE_LZ4
        char* out;
        int r, size; /* LZ4 uses int for size */

        r = dlopen_lz4();
        if (r < 0)
                return r;

        if (src_size <= 8)
                return -EBADMSG;

        size = unaligned_read_le64(src);
        if (size < 0 || (unsigned) size != unaligned_read_le64(src))
                return -EFBIG;
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

int decompress_blob_zstd(
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

        r = dlopen_zstd();
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

        _cleanup_(sym_ZSTD_freeDCtxp) ZSTD_DCtx *dctx = sym_ZSTD_createDCtx();
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
        if (sym_ZSTD_isError(k)) {
                log_debug("ZSTD decoder failed: %s", sym_ZSTD_getErrorName(k));
                return zstd_ret_to_errno(k);
        }
        assert(output.pos >= size);

        *dst_size = size;
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
                size_t* dst_size,
                size_t dst_max) {

        if (compression == COMPRESSION_XZ)
                return decompress_blob_xz(
                                src, src_size,
                                dst, dst_size, dst_max);
        else if (compression == COMPRESSION_LZ4)
                return decompress_blob_lz4(
                                src, src_size,
                                dst, dst_size, dst_max);
        else if (compression == COMPRESSION_ZSTD)
                return decompress_blob_zstd(
                                src, src_size,
                                dst, dst_size, dst_max);
        else
                return -EPROTONOSUPPORT;
}

int decompress_startswith_xz(
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
        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        size_t allocated;
        lzma_ret ret;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        ret = sym_lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        allocated = MALLOC_SIZEOF_SAFE(*buffer);

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

int decompress_startswith_lz4(
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

        r = dlopen_lz4();
        if (r < 0)
                return r;

        if (src_size <= 8)
                return -EBADMSG;

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

int decompress_startswith_zstd(
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

        r = dlopen_zstd();
        if (r < 0)
                return r;

        uint64_t size = sym_ZSTD_getFrameContentSize(src, src_size);
        if (IN_SET(size, ZSTD_CONTENTSIZE_ERROR, ZSTD_CONTENTSIZE_UNKNOWN))
                return -EBADMSG;

        if (size < prefix_len + 1)
                return 0; /* Decompressed text too short to match the prefix and extra */

        _cleanup_(sym_ZSTD_freeDCtxp) ZSTD_DCtx *dctx = sym_ZSTD_createDCtx();
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
        if (sym_ZSTD_isError(k)) {
                log_debug("ZSTD decoder failed: %s", sym_ZSTD_getErrorName(k));
                return zstd_ret_to_errno(k);
        }
        assert(output.pos >= prefix_len + 1);

        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                ((const uint8_t*) *buffer)[prefix_len] == extra;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_startswith(
                Compression compression,
                const void *src,
                uint64_t src_size,
                void **buffer,
                const void *prefix,
                size_t prefix_len,
                uint8_t extra) {

        if (compression == COMPRESSION_XZ)
                return decompress_startswith_xz(
                                src, src_size,
                                buffer,
                                prefix, prefix_len,
                                extra);

        else if (compression == COMPRESSION_LZ4)
                return decompress_startswith_lz4(
                                src, src_size,
                                buffer,
                                prefix, prefix_len,
                                extra);
        else if (compression == COMPRESSION_ZSTD)
                return decompress_startswith_zstd(
                                src, src_size,
                                buffer,
                                prefix, prefix_len,
                                extra);
        else
                return -EBADMSG;
}

int compress_stream_xz(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size) {
        assert(fdf >= 0);
        assert(fdt >= 0);

#if HAVE_XZ
        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        uint8_t buf[BUFSIZ], out[BUFSIZ];
        lzma_action action = LZMA_RUN;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        ret = sym_lzma_easy_encoder(&s, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to initialize XZ encoder: code %u",
                                       ret);

        for (;;) {
                if (s.avail_in == 0 && action == LZMA_RUN) {
                        size_t m = sizeof(buf);
                        ssize_t n;

                        if (max_bytes != UINT64_MAX && (uint64_t) m > max_bytes)
                                m = (size_t) max_bytes;

                        n = read(fdf, buf, m);
                        if (n < 0)
                                return -errno;
                        if (n == 0)
                                action = LZMA_FINISH;
                        else {
                                s.next_in = buf;
                                s.avail_in = n;

                                if (max_bytes != UINT64_MAX) {
                                        assert(max_bytes >= (uint64_t) n);
                                        max_bytes -= n;
                                }
                        }
                }

                if (s.avail_out == 0) {
                        s.next_out = out;
                        s.avail_out = sizeof(out);
                }

                ret = sym_lzma_code(&s, action);
                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Compression failed: code %u",
                                               ret);

                if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
                        ssize_t n, k;

                        n = sizeof(out) - s.avail_out;

                        k = loop_write(fdt, out, n);
                        if (k < 0)
                                return k;

                        if (ret == LZMA_STREAM_END) {
                                if (ret_uncompressed_size)
                                        *ret_uncompressed_size = s.total_in;

                                log_debug("XZ compression finished (%"PRIu64" -> %"PRIu64" bytes, %.1f%%)",
                                          s.total_in, s.total_out,
                                          (double) s.total_out / s.total_in * 100);

                                return 0;
                        }
                }
        }
#else
        return -EPROTONOSUPPORT;
#endif
}

#define LZ4_BUFSIZE (512*1024u)

int compress_stream_lz4(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size) {

#if HAVE_LZ4
        LZ4F_errorCode_t c;
        _cleanup_(sym_LZ4F_freeCompressionContextp) LZ4F_compressionContext_t ctx = NULL;
        _cleanup_free_ void *in_buff = NULL;
        _cleanup_free_ char *out_buff = NULL;
        size_t out_allocsize, n, offset = 0, frame_size;
        uint64_t total_in = 0, total_out;
        int r;
        static const LZ4F_preferences_t preferences = {
                .frameInfo.blockSizeID = 5,
        };

        r = dlopen_lz4();
        if (r < 0)
                return r;

        c = sym_LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
        if (sym_LZ4F_isError(c))
                return -ENOMEM;

        frame_size = sym_LZ4F_compressBound(LZ4_BUFSIZE, &preferences);
        out_allocsize = frame_size + 64*1024; /* add some space for header and trailer */
        out_buff = malloc(out_allocsize);
        if (!out_buff)
                return -ENOMEM;

        in_buff = malloc(LZ4_BUFSIZE);
        if (!in_buff)
                return -ENOMEM;

        n = offset = total_out = sym_LZ4F_compressBegin(ctx, out_buff, out_allocsize, &preferences);
        if (sym_LZ4F_isError(n))
                return -EINVAL;

        log_debug("Buffer size is %zu bytes, header size %zu bytes.", out_allocsize, n);

        for (;;) {
                ssize_t k;

                k = loop_read(fdf, in_buff, LZ4_BUFSIZE, true);
                if (k < 0)
                        return k;
                if (k == 0)
                        break;
                n = sym_LZ4F_compressUpdate(ctx, out_buff + offset, out_allocsize - offset,
                                        in_buff, k, NULL);
                if (sym_LZ4F_isError(n))
                        return -ENOTRECOVERABLE;

                total_in += k;
                offset += n;
                total_out += n;

                if (max_bytes != UINT64_MAX && total_out > (size_t) max_bytes)
                        return log_debug_errno(SYNTHETIC_ERRNO(EFBIG),
                                               "Compressed stream longer than %" PRIu64 " bytes", max_bytes);

                if (out_allocsize - offset < frame_size + 4) {
                        k = loop_write(fdt, out_buff, offset);
                        if (k < 0)
                                return k;
                        offset = 0;
                }
        }

        n = sym_LZ4F_compressEnd(ctx, out_buff + offset, out_allocsize - offset, NULL);
        if (sym_LZ4F_isError(n))
                return -ENOTRECOVERABLE;

        offset += n;
        total_out += n;
        r = loop_write(fdt, out_buff, offset);
        if (r < 0)
                return r;

        if (ret_uncompressed_size)
                *ret_uncompressed_size = total_in;

        log_debug("LZ4 compression finished (%" PRIu64 " -> %" PRIu64 " bytes, %.1f%%)",
                  total_in, total_out,
                  (double) total_out / total_in * 100);

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_stream_xz(int fdf, int fdt, uint64_t max_bytes) {
        assert(fdf >= 0);
        assert(fdt >= 0);

#if HAVE_XZ
        _cleanup_(lzma_end_wrapper) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;

        uint8_t buf[BUFSIZ], out[BUFSIZ];
        lzma_action action = LZMA_RUN;
        int r;

        r = dlopen_lzma();
        if (r < 0)
                return r;

        ret = sym_lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEM),
                                       "Failed to initialize XZ decoder: code %u",
                                       ret);

        for (;;) {
                if (s.avail_in == 0 && action == LZMA_RUN) {
                        ssize_t n;

                        n = read(fdf, buf, sizeof(buf));
                        if (n < 0)
                                return -errno;
                        if (n == 0)
                                action = LZMA_FINISH;
                        else {
                                s.next_in = buf;
                                s.avail_in = n;
                        }
                }

                if (s.avail_out == 0) {
                        s.next_out = out;
                        s.avail_out = sizeof(out);
                }

                ret = sym_lzma_code(&s, action);
                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Decompression failed: code %u",
                                               ret);

                if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
                        ssize_t n, k;

                        n = sizeof(out) - s.avail_out;

                        if (max_bytes != UINT64_MAX) {
                                if (max_bytes < (uint64_t) n)
                                        return -EFBIG;

                                max_bytes -= n;
                        }

                        k = loop_write(fdt, out, n);
                        if (k < 0)
                                return k;

                        if (ret == LZMA_STREAM_END) {
                                log_debug("XZ decompression finished (%"PRIu64" -> %"PRIu64" bytes, %.1f%%)",
                                          s.total_in, s.total_out,
                                          (double) s.total_out / s.total_in * 100);

                                return 0;
                        }
                }
        }
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                               "Cannot decompress file. Compiled without XZ support.");
#endif
}

int decompress_stream_lz4(int in, int out, uint64_t max_bytes) {
#if HAVE_LZ4
        size_t c;
        _cleanup_(sym_LZ4F_freeDecompressionContextp) LZ4F_decompressionContext_t ctx = NULL;
        _cleanup_free_ char *buf = NULL;
        char *src;
        struct stat st;
        int r;
        size_t total_in = 0, total_out = 0;

        r = dlopen_lz4();
        if (r < 0)
                return r;

        c = sym_LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
        if (sym_LZ4F_isError(c))
                return -ENOMEM;

        if (fstat(in, &st) < 0)
                return log_debug_errno(errno, "fstat() failed: %m");

        if (file_offset_beyond_memory_size(st.st_size))
                return -EFBIG;

        buf = malloc(LZ4_BUFSIZE);
        if (!buf)
                return -ENOMEM;

        src = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, in, 0);
        if (src == MAP_FAILED)
                return -errno;

        while (total_in < (size_t) st.st_size) {
                size_t produced = LZ4_BUFSIZE;
                size_t used = st.st_size - total_in;

                c = sym_LZ4F_decompress(ctx, buf, &produced, src + total_in, &used, NULL);
                if (sym_LZ4F_isError(c)) {
                        r = -EBADMSG;
                        goto cleanup;
                }

                total_in += used;
                total_out += produced;

                if (max_bytes != UINT64_MAX && total_out > (size_t) max_bytes) {
                        log_debug("Decompressed stream longer than %"PRIu64" bytes", max_bytes);
                        r = -EFBIG;
                        goto cleanup;
                }

                r = loop_write(out, buf, produced);
                if (r < 0)
                        goto cleanup;
        }

        log_debug("LZ4 decompression finished (%zu -> %zu bytes, %.1f%%)",
                  total_in, total_out,
                  total_in > 0 ? (double) total_out / total_in * 100 : 0.0);
        r = 0;
 cleanup:
        munmap(src, st.st_size);
        return r;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                               "Cannot decompress file. Compiled without LZ4 support.");
#endif
}

int compress_stream_zstd(int fdf, int fdt, uint64_t max_bytes, uint64_t *ret_uncompressed_size) {
        assert(fdf >= 0);
        assert(fdt >= 0);

#if HAVE_ZSTD
        _cleanup_(sym_ZSTD_freeCCtxp) ZSTD_CCtx *cctx = NULL;
        _cleanup_free_ void *in_buff = NULL, *out_buff = NULL;
        size_t in_allocsize, out_allocsize;
        size_t z;
        uint64_t left = max_bytes, in_bytes = 0;
        int r;

        r = dlopen_zstd();
        if (r < 0)
                return r;

        /* Create the context and buffers */
        in_allocsize = sym_ZSTD_CStreamInSize();
        out_allocsize = sym_ZSTD_CStreamOutSize();
        in_buff = malloc(in_allocsize);
        out_buff = malloc(out_allocsize);
        cctx = sym_ZSTD_createCCtx();
        if (!cctx || !out_buff || !in_buff)
                return -ENOMEM;

        z = sym_ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
        if (sym_ZSTD_isError(z))
                log_debug("Failed to enable ZSTD checksum, ignoring: %s", sym_ZSTD_getErrorName(z));

        /* This loop read from the input file, compresses that entire chunk,
         * and writes all output produced to the output file.
         */
        for (;;) {
                bool is_last_chunk;
                ZSTD_inBuffer input = {
                        .src = in_buff,
                        .size = 0,
                        .pos = 0
                };
                ssize_t red;

                red = loop_read(fdf, in_buff, in_allocsize, true);
                if (red < 0)
                        return red;
                is_last_chunk = red == 0;

                in_bytes += (size_t) red;
                input.size = (size_t) red;

                for (bool finished = false; !finished;) {
                        ZSTD_outBuffer output = {
                                .dst = out_buff,
                                .size = out_allocsize,
                                .pos = 0
                        };
                        size_t remaining;
                        ssize_t wrote;

                        /* Compress into the output buffer and write all of the
                         * output to the file so we can reuse the buffer next
                         * iteration.
                         */
                        remaining = sym_ZSTD_compressStream2(
                                cctx, &output, &input,
                                is_last_chunk ? ZSTD_e_end : ZSTD_e_continue);

                        if (sym_ZSTD_isError(remaining)) {
                                log_debug("ZSTD encoder failed: %s", sym_ZSTD_getErrorName(remaining));
                                return zstd_ret_to_errno(remaining);
                        }

                        if (left < output.pos)
                                return -EFBIG;

                        wrote = loop_write_full(fdt, output.dst, output.pos, USEC_INFINITY);
                        if (wrote < 0)
                                return wrote;

                        left -= output.pos;

                        /* If we're on the last chunk we're finished when zstd
                         * returns 0, which means its consumed all the input AND
                         * finished the frame. Otherwise, we're finished when
                         * we've consumed all the input.
                         */
                        finished = is_last_chunk ? (remaining == 0) : (input.pos == input.size);
                }

                /* zstd only returns 0 when the input is completely consumed */
                assert(input.pos == input.size);
                if (is_last_chunk)
                        break;
        }

        if (ret_uncompressed_size)
                *ret_uncompressed_size = in_bytes;

        if (in_bytes > 0)
                log_debug("ZSTD compression finished (%" PRIu64 " -> %" PRIu64 " bytes, %.1f%%)",
                          in_bytes, max_bytes - left, (double) (max_bytes - left) / in_bytes * 100);
        else
                log_debug("ZSTD compression finished (%" PRIu64 " -> %" PRIu64 " bytes)",
                          in_bytes, max_bytes - left);

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_stream_zstd(int fdf, int fdt, uint64_t max_bytes) {
        assert(fdf >= 0);
        assert(fdt >= 0);

#if HAVE_ZSTD
        _cleanup_(sym_ZSTD_freeDCtxp) ZSTD_DCtx *dctx = NULL;
        _cleanup_free_ void *in_buff = NULL, *out_buff = NULL;
        size_t in_allocsize, out_allocsize;
        size_t last_result = 0;
        uint64_t left = max_bytes, in_bytes = 0;
        int r;

        r = dlopen_zstd();
        if (r < 0)
                return r;
        /* Create the context and buffers */
        in_allocsize = sym_ZSTD_DStreamInSize();
        out_allocsize = sym_ZSTD_DStreamOutSize();
        in_buff = malloc(in_allocsize);
        out_buff = malloc(out_allocsize);
        dctx = sym_ZSTD_createDCtx();
        if (!dctx || !out_buff || !in_buff)
                return -ENOMEM;

        /* This loop assumes that the input file is one or more concatenated
         * zstd streams. This example won't work if there is trailing non-zstd
         * data at the end, but streaming decompression in general handles this
         * case. ZSTD_decompressStream() returns 0 exactly when the frame is
         * completed, and doesn't consume input after the frame.
         */
        for (;;) {
                bool has_error = false;
                ZSTD_inBuffer input = {
                        .src = in_buff,
                        .size = 0,
                        .pos = 0
                };
                ssize_t red;

                red = loop_read(fdf, in_buff, in_allocsize, true);
                if (red < 0)
                        return red;
                if (red == 0)
                        break;

                in_bytes += (size_t) red;
                input.size = (size_t) red;
                input.pos = 0;

                /* Given a valid frame, zstd won't consume the last byte of the
                 * frame until it has flushed all of the decompressed data of
                 * the frame. So input.pos < input.size means frame is not done
                 * or there is still output available.
                 */
                while (input.pos < input.size) {
                        ZSTD_outBuffer output = {
                                .dst = out_buff,
                                .size = out_allocsize,
                                .pos = 0
                        };
                        ssize_t wrote;
                        /* The return code is zero if the frame is complete, but
                         * there may be multiple frames concatenated together.
                         * Zstd will automatically reset the context when a
                         * frame is complete. Still, calling ZSTD_DCtx_reset()
                         * can be useful to reset the context to a clean state,
                         * for instance if the last decompression call returned
                         * an error.
                         */
                        last_result = sym_ZSTD_decompressStream(dctx, &output, &input);
                        if (sym_ZSTD_isError(last_result)) {
                                has_error = true;
                                break;
                        }

                        if (left < output.pos)
                                return -EFBIG;

                        wrote = loop_write_full(fdt, output.dst, output.pos, USEC_INFINITY);
                        if (wrote < 0)
                                return wrote;

                        left -= output.pos;
                }
                if (has_error)
                        break;
        }

        if (in_bytes == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "ZSTD decoder failed: no data read");

        if (last_result != 0) {
                /* The last return value from ZSTD_decompressStream did not end
                 * on a frame, but we reached the end of the file! We assume
                 * this is an error, and the input was truncated.
                 */
                log_debug("ZSTD decoder failed: %s", sym_ZSTD_getErrorName(last_result));
                return zstd_ret_to_errno(last_result);
        }

        log_debug(
                "ZSTD decompression finished (%" PRIu64 " -> %" PRIu64 " bytes, %.1f%%)",
                in_bytes,
                max_bytes - left,
                (double) (max_bytes - left) / in_bytes * 100);
        return 0;
#else
        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                               "Cannot decompress file. Compiled without ZSTD support.");
#endif
}

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes) {

        if (endswith(filename, ".lz4"))
                return decompress_stream_lz4(fdf, fdt, max_bytes);
        else if (endswith(filename, ".xz"))
                return decompress_stream_xz(fdf, fdt, max_bytes);
        else if (endswith(filename, ".zst"))
                return decompress_stream_zstd(fdf, fdt, max_bytes);
        else
                return -EPROTONOSUPPORT;
}
