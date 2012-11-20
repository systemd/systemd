/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <lzma.h>

#include "macro.h"
#include "compress.h"

bool compress_blob(const void *src, uint64_t src_size, void *dst, uint64_t *dst_size) {
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        bool b = false;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_size);

        /* Returns false if we couldn't compress the data or the
         * compressed result is longer than the original */

        ret = lzma_easy_encoder(&s, LZMA_PRESET_DEFAULT, LZMA_CHECK_NONE);
        if (ret != LZMA_OK)
                return false;

        s.next_in = src;
        s.avail_in = src_size;
        s.next_out = dst;
        s.avail_out = src_size;

        /* Does it fit? */
        if (lzma_code(&s, LZMA_FINISH) != LZMA_STREAM_END)
                goto fail;

        /* Is it actually shorter? */
        if (s.avail_out == 0)
                goto fail;

        *dst_size = src_size - s.avail_out;
        b = true;

fail:
        lzma_end(&s);

        return b;
}

bool uncompress_blob(const void *src, uint64_t src_size,
                     void **dst, uint64_t *dst_alloc_size, uint64_t* dst_size, uint64_t dst_max) {

        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        uint64_t space;
        bool b = false;

        assert(src);
        assert(src_size > 0);
        assert(dst);
        assert(dst_alloc_size);
        assert(dst_size);
        assert(*dst_alloc_size == 0 || *dst);

        ret = lzma_stream_decoder(&s, UINT64_MAX, 0);
        if (ret != LZMA_OK)
                return false;

        if (*dst_alloc_size <= src_size) {
                void *p;

                p = realloc(*dst, src_size*2);
                if (!p)
                        return false;

                *dst = p;
                *dst_alloc_size = src_size*2;
        }

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *dst;
        space = dst_max > 0 ? MIN(*dst_alloc_size, dst_max) : *dst_alloc_size;
        s.avail_out = space;

        for (;;) {
                void *p;

                ret = lzma_code(&s, LZMA_FINISH);

                if (ret == LZMA_STREAM_END)
                        break;

                if (ret != LZMA_OK)
                        goto fail;

                if (dst_max > 0 && (space - s.avail_out) >= dst_max)
                        break;

                p = realloc(*dst, space*2);
                if (!p)
                        goto fail;

                s.next_out = (uint8_t*) p + ((uint8_t*) s.next_out - (uint8_t*) *dst);
                s.avail_out += space;

                space *= 2;

                *dst = p;
                *dst_alloc_size = space;
        }

        *dst_size = space - s.avail_out;
        b = true;

fail:
        lzma_end(&s);

        return b;
}

bool uncompress_startswith(const void *src, uint64_t src_size,
                           void **buffer, uint64_t *buffer_size,
                           const void *prefix, uint64_t prefix_len,
                           uint8_t extra) {

        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret ret;
        bool b = false;

        /* Checks whether the uncompressed blob starts with the
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
                return false;

        if (*buffer_size <= prefix_len) {
                void *p;

                p = realloc(*buffer, prefix_len*2);
                if (!p)
                        return false;

                *buffer = p;
                *buffer_size = prefix_len*2;
        }

        s.next_in = src;
        s.avail_in = src_size;

        s.next_out = *buffer;
        s.avail_out = *buffer_size;

        for (;;) {
                void *p;

                ret = lzma_code(&s, LZMA_FINISH);

                if (ret != LZMA_STREAM_END && ret != LZMA_OK)
                        goto fail;

                if ((*buffer_size - s.avail_out > prefix_len) &&
                    memcmp(*buffer, prefix, prefix_len) == 0 &&
                    ((const uint8_t*) *buffer)[prefix_len] == extra)
                        break;

                if (ret == LZMA_STREAM_END)
                        goto fail;

                p = realloc(*buffer, *buffer_size*2);
                if (!p)
                        goto fail;

                s.next_out = (uint8_t*) p + ((uint8_t*) s.next_out - (uint8_t*) *buffer);
                s.avail_out += *buffer_size;

                *buffer = p;
                *buffer_size *= 2;
        }

        b = true;

fail:
        lzma_end(&s);

        return b;
}
