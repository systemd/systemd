/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "import-compress.h"
#include "cpu-set-util.h"
#include "env-util.h"
#include "string-table.h"

void import_compress_free(ImportCompress *c) {
        assert(c);

        if (c->type == IMPORT_COMPRESS_XZ)
                lzma_end(&c->xz);
        else if (c->type == IMPORT_COMPRESS_GZIP) {
                if (c->encoding)
                        deflateEnd(&c->gzip);
                else
                        inflateEnd(&c->gzip);
#if HAVE_BZIP2
        } else if (c->type == IMPORT_COMPRESS_BZIP2) {
                if (c->encoding)
                        BZ2_bzCompressEnd(&c->bzip2);
                else
                        BZ2_bzDecompressEnd(&c->bzip2);
#endif
#if HAVE_ZSTD
        } else if (c->type == IMPORT_COMPRESS_ZSTD) {
                if (c->encoding)
                        ZSTD_freeCStream(TAKE_PTR(c->zstd_c));
                else
                        ZSTD_freeDStream(TAKE_PTR(c->zstd_d));
#endif
        }

        c->type = IMPORT_COMPRESS_UNKNOWN;
}

int import_uncompress_detect(ImportCompress *c, const void *data, size_t size) {
        static const uint8_t xz_signature[] = {
                0xfd, '7', 'z', 'X', 'Z', 0x00
        };
        static const uint8_t gzip_signature[] = {
                0x1f, 0x8b
        };
        static const uint8_t bzip2_signature[] = {
                'B', 'Z', 'h'
        };
        static const uint8_t zstd_signature[] = {
                0x28, 0xB5, 0x2F, 0xFD
        };

        int r;

        assert(c);

        if (c->type != IMPORT_COMPRESS_UNKNOWN)
                return 1;

        if (size < MAX4(sizeof(xz_signature),
                        sizeof(gzip_signature),
                        sizeof(bzip2_signature),
                        sizeof(zstd_signature)))
                return 0;

        assert(data);

        if (memcmp(data, xz_signature, sizeof(xz_signature)) == 0) {
                lzma_ret xzr;

                xzr = lzma_stream_decoder(&c->xz, UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED);
                if (xzr != LZMA_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_XZ;

        } else if (memcmp(data, gzip_signature, sizeof(gzip_signature)) == 0) {
                r = inflateInit2(&c->gzip, 15+16);
                if (r != Z_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_GZIP;

#if HAVE_BZIP2
        } else if (memcmp(data, bzip2_signature, sizeof(bzip2_signature)) == 0) {
                r = BZ2_bzDecompressInit(&c->bzip2, 0, 0);
                if (r != BZ_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_BZIP2;
#endif

#if HAVE_ZSTD
        } else if (memcmp(data, zstd_signature, sizeof(zstd_signature)) == 0) {
                unsigned long long r2 = ZSTD_getFrameContentSize(data, size);
                if (r2 == ZSTD_CONTENTSIZE_ERROR)
                        return -EIO;

                assert(c->zstd_d == NULL);
                c->zstd_d = ZSTD_createDStream();
                if (c->zstd_d == NULL)
                        return -ENOMEM;

                c->type = IMPORT_COMPRESS_ZSTD;
#endif
        } else
                c->type = IMPORT_COMPRESS_UNCOMPRESSED;

        c->encoding = false;

        return 1;
}

void import_uncompress_force_off(ImportCompress *c) {
        assert(c);

        c->type = IMPORT_COMPRESS_UNCOMPRESSED;
        c->encoding = false;
}

int import_uncompress(ImportCompress *c, const void *data, size_t size, ImportCompressCallback callback, void *userdata) {
        int r;

        assert(c);
        assert(callback);

        r = import_uncompress_detect(c, data, size);
        if (r <= 0)
                return r;

        if (c->encoding)
                return -EINVAL;

        if (size <= 0)
                return 1;

        assert(data);

        switch (c->type) {

        case IMPORT_COMPRESS_UNCOMPRESSED:
                r = callback(data, size, userdata);
                if (r < 0)
                        return r;

                break;

        case IMPORT_COMPRESS_XZ:
                c->xz.next_in = data;
                c->xz.avail_in = size;

                while (c->xz.avail_in > 0) {
                        uint8_t buffer[16 * 1024];
                        lzma_ret lzr;

                        c->xz.next_out = buffer;
                        c->xz.avail_out = sizeof(buffer);

                        lzr = lzma_code(&c->xz, LZMA_RUN);
                        if (!IN_SET(lzr, LZMA_OK, LZMA_STREAM_END))
                                return -EIO;

                        if (c->xz.avail_out < sizeof(buffer)) {
                                r = callback(buffer, sizeof(buffer) - c->xz.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;

        case IMPORT_COMPRESS_GZIP:
                c->gzip.next_in = (void*) data;
                c->gzip.avail_in = size;

                while (c->gzip.avail_in > 0) {
                        uint8_t buffer[16 * 1024];

                        c->gzip.next_out = buffer;
                        c->gzip.avail_out = sizeof(buffer);

                        r = inflate(&c->gzip, Z_NO_FLUSH);
                        if (!IN_SET(r, Z_OK, Z_STREAM_END))
                                return -EIO;

                        if (c->gzip.avail_out < sizeof(buffer)) {
                                r = callback(buffer, sizeof(buffer) - c->gzip.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;

#if HAVE_BZIP2
        case IMPORT_COMPRESS_BZIP2:
                c->bzip2.next_in = (void*) data;
                c->bzip2.avail_in = size;

                while (c->bzip2.avail_in > 0) {
                        uint8_t buffer[16 * 1024];

                        c->bzip2.next_out = (char*) buffer;
                        c->bzip2.avail_out = sizeof(buffer);

                        r = BZ2_bzDecompress(&c->bzip2);
                        if (!IN_SET(r, BZ_OK, BZ_STREAM_END))
                                return -EIO;

                        if (c->bzip2.avail_out < sizeof(buffer)) {
                                r = callback(buffer, sizeof(buffer) - c->bzip2.avail_out, userdata);
                                if (r < 0)
                                        return r;
                        }
                }

                break;
#endif

#if HAVE_ZSTD
        case IMPORT_COMPRESS_ZSTD: {
                ZSTD_inBuffer in = {
                        .src = data,
                        .size = size
                };
                ZSTD_outBuffer out = {
                        .dst = newa(uint8_t, ZSTD_DStreamOutSize()),
                        .size = ZSTD_DStreamOutSize()
                };

                while (in.pos < in.size) {
                        size_t ret = ZSTD_decompressStream(c->zstd_d, &out, &in);
                        if (ZSTD_isError(ret))
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EIO),
                                                "Failed to decompress zstd stream: %s",
                                                ZSTD_getErrorName(ret));

                        if (out.pos != 0) {
                                r = callback(out.dst, out.pos, userdata);
                                if (r < 0)
                                        return r;
                                out.pos = 0;
                        }
                }

                break;
        }
#endif

        default:
                assert_not_reached();
        }

        return 1;
}

int import_compress_init(ImportCompress *c, ImportCompressType t) {
        int r;

        assert(c);

        switch (t) {

        case IMPORT_COMPRESS_XZ: {
                lzma_ret xzr;

                xzr = lzma_easy_encoder(&c->xz, LZMA_PRESET_DEFAULT, LZMA_CHECK_CRC64);
                if (xzr != LZMA_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_XZ;
                break;
        }

        case IMPORT_COMPRESS_GZIP:
                r = deflateInit2(&c->gzip, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
                if (r != Z_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_GZIP;
                break;

#if HAVE_BZIP2
        case IMPORT_COMPRESS_BZIP2:
                r = BZ2_bzCompressInit(&c->bzip2, 9, 0, 0);
                if (r != BZ_OK)
                        return -EIO;

                c->type = IMPORT_COMPRESS_BZIP2;
                break;
#endif

#if HAVE_ZSTD
        case IMPORT_COMPRESS_ZSTD: {
                size_t r2;
                int level = ZSTD_CLEVEL_DEFAULT;
                int ncpus;
                int64_t env;

                assert(c->zstd_c == NULL);
                c->zstd_c = ZSTD_createCStream();
                if (c->zstd_c == NULL)
                        return -ENOMEM;

                r = getenv_int64("SYSTEMD_IMPORT_COMPRESS_LEVEL_ZSTD", &env);
                if (r >= 0 && env != 0 && IN_RANGE(env, ZSTD_minCLevel(), ZSTD_maxCLevel()))
                        level = (int)env;
                else if (r >= 0)
                        log_warning("Invalid value of $SYSTEMD_IMPORT_COMPRESS_LEVEL_ZSTD (%" PRIi64 "), ignoring", env);
                else if (r != -ENXIO)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_IMPORT_COMPRESS_LEVEL_ZSTD: %m");

                /* TODO: better default? zstd -3 is really weak */
                r2 = ZSTD_CCtx_setParameter(c->zstd_c, ZSTD_c_compressionLevel, level);
                if (ZSTD_isError(r2))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIO),
                                        "Failed to set zstd compression level to %d: %s",
                                        level,
                                        ZSTD_getErrorName(r2));

                r2 = ZSTD_CCtx_setParameter(c->zstd_c, ZSTD_c_checksumFlag, 1);
                if (ZSTD_isError(r2))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIO),
                                        "Failed to enable zstd output checksumming: %s",
                                        ZSTD_getErrorName(r2));

                ncpus = cpus_in_affinity_mask();
                if (ncpus > 0) {
                        r2 = ZSTD_CCtx_setParameter(c->zstd_c, ZSTD_c_nbWorkers, ncpus);
                        if (!ZSTD_isError(r2))
                                log_debug("Enabled zstd multithreaded compression with %d threads", ncpus);
                        else
                                log_warning("Failed to enable zstd multithreaded compression with %d threads, ignoring: %s",
                                            ncpus,
                                            ZSTD_getErrorName(r2));
                } else
                        log_warning_errno(
                                        ncpus,
                                        "Failed to determine available CPUs, not enabling zstd multithreaded compression: %m");

                c->type = IMPORT_COMPRESS_ZSTD;
                break;
        }
#endif

        case IMPORT_COMPRESS_UNCOMPRESSED:
                c->type = IMPORT_COMPRESS_UNCOMPRESSED;
                break;

        default:
                return -EOPNOTSUPP;
        }

        c->encoding = true;
        return 0;
}

static int enlarge_buffer(void **buffer, const size_t *buffer_size, size_t *buffer_allocated) {
        size_t l;
        void *p;

        if (*buffer_allocated > *buffer_size)
                return 0;

        l = MAX(16*1024U, (*buffer_size * 2));
        p = realloc(*buffer, l);
        if (!p)
                return -ENOMEM;

        *buffer = p;
        *buffer_allocated = l;

        return 1;
}

int import_compress(ImportCompress *c, const void *data, size_t size, void **buffer, size_t *buffer_size, size_t *buffer_allocated) {
        int r;

        assert(c);
        assert(buffer);
        assert(buffer_size);
        assert(buffer_allocated);

        if (!c->encoding)
                return -EINVAL;

        if (size <= 0)
                return 0;

        assert(data);

        *buffer_size = 0;

        switch (c->type) {

        case IMPORT_COMPRESS_XZ:

                c->xz.next_in = data;
                c->xz.avail_in = size;

                while (c->xz.avail_in > 0) {
                        lzma_ret lzr;

                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->xz.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->xz.avail_out = *buffer_allocated - *buffer_size;

                        lzr = lzma_code(&c->xz, LZMA_RUN);
                        if (lzr != LZMA_OK)
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->xz.avail_out;
                }

                break;

        case IMPORT_COMPRESS_GZIP:

                c->gzip.next_in = (void*) data;
                c->gzip.avail_in = size;

                while (c->gzip.avail_in > 0) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->gzip.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->gzip.avail_out = *buffer_allocated - *buffer_size;

                        r = deflate(&c->gzip, Z_NO_FLUSH);
                        if (r != Z_OK)
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->gzip.avail_out;
                }

                break;

#if HAVE_BZIP2
        case IMPORT_COMPRESS_BZIP2:

                c->bzip2.next_in = (void*) data;
                c->bzip2.avail_in = size;

                while (c->bzip2.avail_in > 0) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->bzip2.next_out = (void*) ((uint8_t*) *buffer + *buffer_size);
                        c->bzip2.avail_out = *buffer_allocated - *buffer_size;

                        r = BZ2_bzCompress(&c->bzip2, BZ_RUN);
                        if (r != BZ_RUN_OK)
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->bzip2.avail_out;
                }

                break;
#endif

#if HAVE_ZSTD
        case IMPORT_COMPRESS_ZSTD: {
                /*
                 * In theory, this says whether this is likely to be the last input chunk. However,
                 * we have no reliable way of determining EOFs because our compression is streaming.
                 *
                 * NOTE: if this changes, be sure to call ZSTD_compressStream2(..., ZSTD_e_end) repeatedly
                 * until it starts returning 0, i.e. it is allowed to call ZSTD_compressStream2(ZSTD_e_continue)
                 * after ZSTD_compressStream2(..., ZSTD_e_end), but only after the latter call has returned 0
                 * at least once.
                 * */
                const ZSTD_EndDirective mode = ZSTD_e_continue;
                /* zstd-recommended size of the output buffer */
                const size_t initial = ZSTD_CStreamOutSize();
                /* Let's use libzstd data structure to keep track of the buffer.
                 * Copy the pointers back on exit */
                ZSTD_outBuffer out = {
                        .dst = *buffer,
                        .pos = *buffer_size,
                        .size = *buffer_allocated,
                };
                ZSTD_inBuffer in = {
                        .src = data,
                        .size = size,
                };

                /* Make sure that we start with at least ZSTD_CStreamOutSize()-sized buffer */
                if (out.size < initial) {
                        r = enlarge_buffer(&out.dst, &initial, &out.size);
                        if (r < 0)
                                return r;
                }

                while (in.pos < in.size) {
                        r = enlarge_buffer(&out.dst, &out.pos, &out.size);
                        if (r < 0)
                                return r;

                        size_t remaining = ZSTD_compressStream2(c->zstd_c, &out, &in, mode);
                        if (ZSTD_isError(remaining))
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EIO),
                                                "Failed to compress into zstd stream: %s",
                                                ZSTD_getErrorName(remaining));
                        /* remaining > 0, but we are not using that here */
                }

                /* Write back the pointers */
                *buffer = out.dst;
                *buffer_size = out.pos;
                *buffer_allocated = out.size;
                break;
        }
#endif

        case IMPORT_COMPRESS_UNCOMPRESSED:

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

int import_compress_finish(ImportCompress *c, void **buffer, size_t *buffer_size, size_t *buffer_allocated) {
        int r;

        assert(c);
        assert(buffer);
        assert(buffer_size);
        assert(buffer_allocated);

        if (!c->encoding)
                return -EINVAL;

        *buffer_size = 0;

        switch (c->type) {

        case IMPORT_COMPRESS_XZ: {
                lzma_ret lzr;

                c->xz.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->xz.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->xz.avail_out = *buffer_allocated - *buffer_size;

                        lzr = lzma_code(&c->xz, LZMA_FINISH);
                        if (!IN_SET(lzr, LZMA_OK, LZMA_STREAM_END))
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->xz.avail_out;
                } while (lzr != LZMA_STREAM_END);

                break;
        }

        case IMPORT_COMPRESS_GZIP:
                c->gzip.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->gzip.next_out = (uint8_t*) *buffer + *buffer_size;
                        c->gzip.avail_out = *buffer_allocated - *buffer_size;

                        r = deflate(&c->gzip, Z_FINISH);
                        if (!IN_SET(r, Z_OK, Z_STREAM_END))
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->gzip.avail_out;
                } while (r != Z_STREAM_END);

                break;

#if HAVE_BZIP2
        case IMPORT_COMPRESS_BZIP2:
                c->bzip2.avail_in = 0;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        c->bzip2.next_out = (void*) ((uint8_t*) *buffer + *buffer_size);
                        c->bzip2.avail_out = *buffer_allocated - *buffer_size;

                        r = BZ2_bzCompress(&c->bzip2, BZ_FINISH);
                        if (!IN_SET(r, BZ_FINISH_OK, BZ_STREAM_END))
                                return -EIO;

                        *buffer_size += (*buffer_allocated - *buffer_size) - c->bzip2.avail_out;
                } while (r != BZ_STREAM_END);

                break;
#endif

#if HAVE_ZSTD
        case IMPORT_COMPRESS_ZSTD: {
                const ZSTD_EndDirective mode = ZSTD_e_end;
                /* Let's use libzstd data structure to keep track of the buffer.
                 * Copy the pointers back on exit */
                ZSTD_outBuffer out = {
                        .dst = *buffer,
                        .pos = *buffer_size,
                        .size = *buffer_allocated,
                };
                /* According to the example, we're supposed to pass the last data buffer
                 * on the last iteration, but we don't have it here -- pass NULL */
                ZSTD_inBuffer in = {
                        .src = NULL,
                        .size = 0,
                };

                /* We're done when zstd returns 0 */
                size_t remaining;
                do {
                        r = enlarge_buffer(&out.dst, &out.pos, &out.size);
                        if (r < 0)
                                return r;

                        remaining = ZSTD_compressStream2(c->zstd_c, &out, &in, mode);
                        if (ZSTD_isError(remaining))
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(EIO),
                                                "Failed to finalize zstd stream: %s",
                                                ZSTD_getErrorName(remaining));
                } while (remaining > 0);

                /* Write back the pointers */
                *buffer = out.dst;
                *buffer_size = out.pos;
                *buffer_allocated = out.size;
                break;
        }
#endif

        case IMPORT_COMPRESS_UNCOMPRESSED:
                break;

        default:
                return -EOPNOTSUPP;
        }

        return 0;
}
