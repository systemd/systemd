/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "import-compress.h"
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
                if (c->encoding) {
                        ZSTD_freeCCtx(c->c_zstd);
                        c->c_zstd = NULL;
                } else {
                        ZSTD_freeDCtx(c->d_zstd);
                        c->d_zstd = NULL;
                }
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
                0x28, 0xb5, 0x2f, 0xfd
        };

        int r;

        assert(c);

        if (c->type != IMPORT_COMPRESS_UNKNOWN)
                return 1;

        if (size < MAX4(sizeof(xz_signature),
                        sizeof(gzip_signature),
                        sizeof(zstd_signature),
                        sizeof(bzip2_signature)))
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
                c->d_zstd = ZSTD_createDCtx();
                if (!c->d_zstd)
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
                ZSTD_inBuffer input = {
                        .src =  (void*) data,
                        .size = size,
                };

                while (input.pos < input.size) {
                        uint8_t buffer[16 * 1024];
                        ZSTD_outBuffer output = {
                                .dst = buffer,
                                .size = sizeof(buffer),
                        };
                        size_t res;

                        res = ZSTD_decompressStream(c->d_zstd, &output, &input);
                        if (ZSTD_isError(res))
                                return -EIO;

                        if (output.pos > 0) {
                                r = callback(output.dst, output.pos, userdata);
                                if (r < 0)
                                        return r;
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
        case IMPORT_COMPRESS_ZSTD:
                c->c_zstd = ZSTD_createCCtx();
                if (!c->c_zstd)
                        return -ENOMEM;

                r = ZSTD_CCtx_setParameter(c->c_zstd, ZSTD_c_compressionLevel, ZSTD_CLEVEL_DEFAULT);
                if (ZSTD_isError(r))
                        return -EIO;

                c->type = IMPORT_COMPRESS_ZSTD;
                break;
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

static int enlarge_buffer(void **buffer, size_t *buffer_size, size_t *buffer_allocated) {
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
                ZSTD_inBuffer input = {
                        .src = data,
                        .size = size,
                };

                while (input.pos < input.size) {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        ZSTD_outBuffer output = {
                                .dst = ((uint8_t *) *buffer + *buffer_size),
                                .size = *buffer_allocated - *buffer_size,
                        };
                        size_t res;

                        res = ZSTD_compressStream2(c->c_zstd, &output, &input, ZSTD_e_continue);
                        if (ZSTD_isError(res))
                                return -EIO;

                        *buffer_size += output.pos;
                }

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
                ZSTD_inBuffer input = {};
                size_t res;

                do {
                        r = enlarge_buffer(buffer, buffer_size, buffer_allocated);
                        if (r < 0)
                                return r;

                        ZSTD_outBuffer output = {
                                .dst = ((uint8_t *) *buffer + *buffer_size),
                                .size = *buffer_allocated - *buffer_size,
                        };

                        res = ZSTD_compressStream2(c->c_zstd, &output, &input, ZSTD_e_end);
                        if (ZSTD_isError(res))
                                return -EIO;

                        *buffer_size += output.pos;
                } while (res != 0);

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

static const char* const import_compress_type_table[_IMPORT_COMPRESS_TYPE_MAX] = {
        [IMPORT_COMPRESS_UNKNOWN] = "unknown",
        [IMPORT_COMPRESS_UNCOMPRESSED] = "uncompressed",
        [IMPORT_COMPRESS_XZ] = "xz",
        [IMPORT_COMPRESS_GZIP] = "gzip",
#if HAVE_BZIP2
        [IMPORT_COMPRESS_BZIP2] = "bzip2",
#endif
#if HAVE_ZSTD
        [IMPORT_COMPRESS_ZSTD] = "zstd",
#endif
};

DEFINE_STRING_TABLE_LOOKUP(import_compress_type, ImportCompressType);
