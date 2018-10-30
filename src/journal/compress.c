/* SPDX-License-Identifier: LGPL-2.1+ */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if HAVE_XZ
#include <lzma.h>
#endif

#if HAVE_LZ4
#include <lz4.h>
#include <lz4frame.h>
#endif

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "io-util.h"
#include "journal-def.h"
#include "macro.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

#if HAVE_LZ4
DEFINE_TRIVIAL_CLEANUP_FUNC(LZ4F_compressionContext_t, LZ4F_freeCompressionContext);
DEFINE_TRIVIAL_CLEANUP_FUNC(LZ4F_decompressionContext_t, LZ4F_freeDecompressionContext);
#endif

#define ALIGN_8(l) ALIGN_TO(l, sizeof(size_t))

static const char* const object_compressed_table[_OBJECT_COMPRESSED_MAX] = {
        [OBJECT_COMPRESSED_XZ] = "XZ",
        [OBJECT_COMPRESSED_LZ4] = "LZ4",
};

DEFINE_STRING_TABLE_LOOKUP(object_compressed, int);

int compress_blob_xz(const void *src, uint64_t src_size,
                     void *dst, size_t dst_alloc_size, size_t *dst_size) {
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

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 80)
                return -ENOBUFS;

        ret = lzma_stream_buffer_encode((lzma_filter*) filters, LZMA_CHECK_NONE, NULL,
                                        src, src_size, dst, &out_pos, dst_alloc_size);
        if (ret != LZMA_OK)
                return -ENOBUFS;

        *dst_size = out_pos;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int compress_blob_lz4(const void *src, uint64_t src_size,
                      void *dst, size_t dst_alloc_size, size_t *dst_size) {
#if HAVE_LZ4
        int r;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size > 0);
        assert(dst_size);

        /* Returns < 0 if we couldn't compress the data or the
         * compressed result is longer than the original */

        if (src_size < 9)
                return -ENOBUFS;

        r = LZ4_compress_default(src, (char*)dst + 8, src_size, (int) dst_alloc_size - 8);
        if (r <= 0)
                return -ENOBUFS;

        *(le64_t*) dst = htole64(src_size);
        *dst_size = r + 8;

        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob_xz(const void *src, uint64_t src_size,
                       void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max) {

#if HAVE_XZ
        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        size_t space;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size);
        assert(dst_size);
        assert(*dst_alloc_size == 0 || *dst);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return -ENOMEM;

        space = MIN(src_size * 2, dst_max ?: (size_t) -1);
        if (!greedy_realloc(dst, dst_alloc_size, space, 1))
                return -ENOMEM;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *dst;
        s.avail_out = space;

        for (;;) {
                size_t used;

                ret = lzma_code(&s, LZMA_FINISH);

                if (ret == LZMA_STREAM_END)
                        break;
                else if (ret != LZMA_OK)
                        return -ENOMEM;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;
                else if (dst_max > 0 && space == dst_max)
                        return -ENOBUFS;

                used = space - s.avail_out;
                space = MIN(2 * space, dst_max ?: (size_t) -1);
                if (!greedy_realloc(dst, dst_alloc_size, space, 1))
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

int decompress_blob_lz4(const void *src, uint64_t src_size,
                        void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max) {

#if HAVE_LZ4
        char* out;
        int r, size; /* LZ4 uses int for size */

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size);
        assert(dst_size);
        assert(*dst_alloc_size == 0 || *dst);

        if (src_size <= 8)
                return -EBADMSG;

        size = le64toh( *(le64_t*)src );
        if (size < 0 || (unsigned) size != le64toh(*(le64_t*)src))
                return -EFBIG;
        if ((size_t) size > *dst_alloc_size) {
                out = realloc(*dst, size);
                if (!out)
                        return -ENOMEM;
                *dst = out;
                *dst_alloc_size = size;
        } else
                out = *dst;

        r = LZ4_decompress_safe((char*)src + 8, out, src_size - 8, size);
        if (r < 0 || r != size)
                return -EBADMSG;

        *dst_size = size;
        return 0;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_blob(int compression,
                    const void *src, uint64_t src_size,
                    void **dst, size_t *dst_alloc_size, size_t* dst_size, size_t dst_max) {
        if (compression == OBJECT_COMPRESSED_XZ)
                return decompress_blob_xz(src, src_size,
                                          dst, dst_alloc_size, dst_size, dst_max);
        else if (compression == OBJECT_COMPRESSED_LZ4)
                return decompress_blob_lz4(src, src_size,
                                           dst, dst_alloc_size, dst_size, dst_max);
        else
                return -EBADMSG;
}

int decompress_startswith_xz(const void *src, uint64_t src_size,
                             void **buffer, size_t *buffer_size,
                             const void *prefix, size_t prefix_len,
                             uint8_t extra) {

#if HAVE_XZ
        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;

        /* Checks whether the decompressed blob starts with the
         * mentioned prefix. The byte extra needs to follow the
         * prefix */

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(buffer_size);
        assert(prefix);
        assert(*buffer_size == 0 || *buffer);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, buffer_size, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = *buffer_size;

        for (;;) {
                ret = lzma_code(&s, LZMA_FINISH);

                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END))
                        return -EBADMSG;

                if (*buffer_size - s.avail_out >= prefix_len + 1)
                        return memcmp(*buffer, prefix, prefix_len) == 0 &&
                                ((const uint8_t*) *buffer)[prefix_len] == extra;

                if (ret == LZMA_STREAM_END)
                        return 0;

                s.avail_out += *buffer_size;

                if (!(greedy_realloc(buffer, buffer_size, *buffer_size * 2, 1)))
                        return -ENOMEM;

                s.next_out = *(uint8_t**)buffer + *buffer_size - s.avail_out;
        }

#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_startswith_lz4(const void *src, uint64_t src_size,
                              void **buffer, size_t *buffer_size,
                              const void *prefix, size_t prefix_len,
                              uint8_t extra) {
#if HAVE_LZ4
        /* Checks whether the decompressed blob starts with the
         * mentioned prefix. The byte extra needs to follow the
         * prefix */

        int r;

        assert(src);
        assert(src_size > 0);
        assert(buffer);
        assert(buffer_size);
        assert(prefix);
        assert(*buffer_size == 0 || *buffer);

        if (src_size <= 8)
                return -EBADMSG;

        if (!(greedy_realloc(buffer, buffer_size, ALIGN_8(prefix_len + 1), 1)))
                return -ENOMEM;

        r = LZ4_decompress_safe_partial((char*)src + 8, *buffer, src_size - 8,
                                        prefix_len + 1, *buffer_size);
        /* One lz4 < 1.8.3, we might get "failure" (r < 0), or "success" where
         * just a part of the buffer is decompressed. But if we get a smaller
         * amount of bytes than requested, we don't know whether there isn't enough
         * data to fill the requested size or whether we just got a partial answer.
         */
        if (r < 0 || (size_t) r < prefix_len + 1) {
                size_t size;

                if (LZ4_versionNumber() >= 10803)
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
                r = decompress_blob_lz4(src, src_size, buffer, buffer_size, &size, 0);
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

int decompress_startswith(int compression,
                          const void *src, uint64_t src_size,
                          void **buffer, size_t *buffer_size,
                          const void *prefix, size_t prefix_len,
                          uint8_t extra) {
        if (compression == OBJECT_COMPRESSED_XZ)
                return decompress_startswith_xz(src, src_size,
                                                buffer, buffer_size,
                                                prefix, prefix_len,
                                                extra);
        else if (compression == OBJECT_COMPRESSED_LZ4)
                return decompress_startswith_lz4(src, src_size,
                                                 buffer, buffer_size,
                                                 prefix, prefix_len,
                                                 extra);
        else
                return -EBADMSG;
}

int compress_stream_xz(int fdf, int fdt, uint64_t max_bytes) {
#if HAVE_XZ
        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        uint8_t buf[BUFSIZ], out[BUFSIZ];
        lzma_action action = LZMA_RUN;

        assert(fdf >= 0);
        assert(fdt >= 0);

        ret = lzma_easy_encoder(&s, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
        if (ret != LZMA_OK) {
                log_error("Failed to initialize XZ encoder: code %u", ret);
                return -EINVAL;
        }

        for (;;) {
                if (s.avail_in == 0 && action == LZMA_RUN) {
                        size_t m = sizeof(buf);
                        ssize_t n;

                        if (max_bytes != (uint64_t) -1 && (uint64_t) m > max_bytes)
                                m = (size_t) max_bytes;

                        n = read(fdf, buf, m);
                        if (n < 0)
                                return -errno;
                        if (n == 0)
                                action = LZMA_FINISH;
                        else {
                                s.next_in = buf;
                                s.avail_in = n;

                                if (max_bytes != (uint64_t) -1) {
                                        assert(max_bytes >= (uint64_t) n);
                                        max_bytes -= n;
                                }
                        }
                }

                if (s.avail_out == 0) {
                        s.next_out = out;
                        s.avail_out = sizeof(out);
                }

                ret = lzma_code(&s, action);
                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END)) {
                        log_error("Compression failed: code %u", ret);
                        return -EBADMSG;
                }

                if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
                        ssize_t n, k;

                        n = sizeof(out) - s.avail_out;

                        k = loop_write(fdt, out, n, false);
                        if (k < 0)
                                return k;

                        if (ret == LZMA_STREAM_END) {
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

int compress_stream_lz4(int fdf, int fdt, uint64_t max_bytes) {

#if HAVE_LZ4
        LZ4F_errorCode_t c;
        _cleanup_(LZ4F_freeCompressionContextp) LZ4F_compressionContext_t ctx = NULL;
        _cleanup_free_ char *buf = NULL;
        char *src = NULL;
        size_t size, n, total_in = 0, total_out, offset = 0, frame_size;
        struct stat st;
        int r;
        static const LZ4F_compressOptions_t options = {
                .stableSrc = 1,
        };
        static const LZ4F_preferences_t preferences = {
                .frameInfo.blockSizeID = 5,
        };

        c = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
        if (LZ4F_isError(c))
                return -ENOMEM;

        if (fstat(fdf, &st) < 0)
                return log_debug_errno(errno, "fstat() failed: %m");

        frame_size = LZ4F_compressBound(LZ4_BUFSIZE, &preferences);
        size =  frame_size + 64*1024; /* add some space for header and trailer */
        buf = malloc(size);
        if (!buf)
                return -ENOMEM;

        n = offset = total_out = LZ4F_compressBegin(ctx, buf, size, &preferences);
        if (LZ4F_isError(n))
                return -EINVAL;

        src = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fdf, 0);
        if (src == MAP_FAILED)
                return -errno;

        log_debug("Buffer size is %zu bytes, header size %zu bytes.", size, n);

        while (total_in < (size_t) st.st_size) {
                ssize_t k;

                k = MIN(LZ4_BUFSIZE, st.st_size - total_in);
                n = LZ4F_compressUpdate(ctx, buf + offset, size - offset,
                                        src + total_in, k, &options);
                if (LZ4F_isError(n)) {
                        r = -ENOTRECOVERABLE;
                        goto cleanup;
                }

                total_in += k;
                offset += n;
                total_out += n;

                if (max_bytes != (uint64_t) -1 && total_out > (size_t) max_bytes) {
                        log_debug("Compressed stream longer than %"PRIu64" bytes", max_bytes);
                        return -EFBIG;
                }

                if (size - offset < frame_size + 4) {
                        k = loop_write(fdt, buf, offset, false);
                        if (k < 0) {
                                r = k;
                                goto cleanup;
                        }
                        offset = 0;
                }
        }

        n = LZ4F_compressEnd(ctx, buf + offset, size - offset, &options);
        if (LZ4F_isError(n)) {
                r = -ENOTRECOVERABLE;
                goto cleanup;
        }

        offset += n;
        total_out += n;
        r = loop_write(fdt, buf, offset, false);
        if (r < 0)
                goto cleanup;

        log_debug("LZ4 compression finished (%zu -> %zu bytes, %.1f%%)",
                  total_in, total_out,
                  (double) total_out / total_in * 100);
 cleanup:
        munmap(src, st.st_size);
        return r;
#else
        return -EPROTONOSUPPORT;
#endif
}

int decompress_stream_xz(int fdf, int fdt, uint64_t max_bytes) {

#if HAVE_XZ
        _cleanup_(lzma_end) lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;

        uint8_t buf[BUFSIZ], out[BUFSIZ];
        lzma_action action = LZMA_RUN;

        assert(fdf >= 0);
        assert(fdt >= 0);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK) {
                log_debug("Failed to initialize XZ decoder: code %u", ret);
                return -ENOMEM;
        }

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

                ret = lzma_code(&s, action);
                if (!IN_SET(ret, LZMA_OK, LZMA_STREAM_END)) {
                        log_debug("Decompression failed: code %u", ret);
                        return -EBADMSG;
                }

                if (s.avail_out == 0 || ret == LZMA_STREAM_END) {
                        ssize_t n, k;

                        n = sizeof(out) - s.avail_out;

                        if (max_bytes != (uint64_t) -1) {
                                if (max_bytes < (uint64_t) n)
                                        return -EFBIG;

                                max_bytes -= n;
                        }

                        k = loop_write(fdt, out, n, false);
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
        log_debug("Cannot decompress file. Compiled without XZ support.");
        return -EPROTONOSUPPORT;
#endif
}

int decompress_stream_lz4(int in, int out, uint64_t max_bytes) {
#if HAVE_LZ4
        size_t c;
        _cleanup_(LZ4F_freeDecompressionContextp) LZ4F_decompressionContext_t ctx = NULL;
        _cleanup_free_ char *buf = NULL;
        char *src;
        struct stat st;
        int r = 0;
        size_t total_in = 0, total_out = 0;

        c = LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
        if (LZ4F_isError(c))
                return -ENOMEM;

        if (fstat(in, &st) < 0)
                return log_debug_errno(errno, "fstat() failed: %m");

        buf = malloc(LZ4_BUFSIZE);
        if (!buf)
                return -ENOMEM;

        src = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, in, 0);
        if (src == MAP_FAILED)
                return -errno;

        while (total_in < (size_t) st.st_size) {
                size_t produced = LZ4_BUFSIZE;
                size_t used = st.st_size - total_in;

                c = LZ4F_decompress(ctx, buf, &produced, src + total_in, &used, NULL);
                if (LZ4F_isError(c)) {
                        r = -EBADMSG;
                        goto cleanup;
                }

                total_in += used;
                total_out += produced;

                if (max_bytes != (uint64_t) -1 && total_out > (size_t) max_bytes) {
                        log_debug("Decompressed stream longer than %"PRIu64" bytes", max_bytes);
                        r = -EFBIG;
                        goto cleanup;
                }

                r = loop_write(out, buf, produced, false);
                if (r < 0)
                        goto cleanup;
        }

        log_debug("LZ4 decompression finished (%zu -> %zu bytes, %.1f%%)",
                  total_in, total_out,
                  total_in > 0 ? (double) total_out / total_in * 100 : 0.0);
 cleanup:
        munmap(src, st.st_size);
        return r;
#else
        log_debug("Cannot decompress file. Compiled without LZ4 support.");
        return -EPROTONOSUPPORT;
#endif
}

int decompress_stream(const char *filename, int fdf, int fdt, uint64_t max_bytes) {

        if (endswith(filename, ".lz4"))
                return decompress_stream_lz4(fdf, fdt, max_bytes);
        else if (endswith(filename, ".xz"))
                return decompress_stream_xz(fdf, fdt, max_bytes);
        else
                return -EPROTONOSUPPORT;
}
