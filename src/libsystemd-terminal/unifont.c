/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 David Herrmann <dh.herrmann@gmail.com>

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

/*
 * Unifont
 * This implements the unifont glyph-array parser and provides it via a simple
 * API to the caller. No heavy transformations are performed so glyph-lookups
 * stay as fast as possible.
 */

#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "macro.h"
#include "unifont-def.h"
#include "unifont.h"
#include "util.h"

struct unifont {
        unsigned long ref;

        int fd;
        const uint8_t *map;
        size_t size;

        unifont_header header;
        const void *glyphs;     /* unaligned! */
        size_t n_glyphs;
        size_t glyphsize;
};

static int unifont_fetch_header(unifont *u) {
        unifont_header h = { };
        uint64_t glyphsize;

        if (u->size < UNIFONT_HEADER_SIZE_MIN)
                return -EBFONT;

        assert_cc(sizeof(h) >= UNIFONT_HEADER_SIZE_MIN);
        memcpy(&h, u->map, UNIFONT_HEADER_SIZE_MIN);

        h.compatible_flags = le32toh(h.compatible_flags);
        h.incompatible_flags = le32toh(h.incompatible_flags);
        h.header_size = le32toh(h.header_size);
        h.glyph_header_size = le16toh(h.glyph_header_size);
        h.glyph_stride = le16toh(h.glyph_stride);
        h.glyph_body_size = le64toh(h.glyph_body_size);

        if (memcmp(h.signature, "DVDHRMUF", 8))
                return -EBFONT;
        if (h.incompatible_flags != 0)
                return -EBFONT;
        if (h.header_size < UNIFONT_HEADER_SIZE_MIN || h.header_size > u->size)
                return -EBFONT;
        if (h.glyph_header_size + h.glyph_body_size < h.glyph_header_size)
                return -EBFONT;
        if (h.glyph_stride * 16ULL > h.glyph_body_size)
                return -EBFONT;

        glyphsize = h.glyph_header_size + h.glyph_body_size;

        if (glyphsize == 0 || glyphsize > u->size - h.header_size) {
                u->n_glyphs = 0;
        } else {
                u->glyphs = u->map + h.header_size;
                u->n_glyphs = (u->size - h.header_size) / glyphsize;
                u->glyphsize = glyphsize;
        }

        memcpy(&u->header, &h, sizeof(h));
        return 0;
}

static int unifont_fetch_glyph(unifont *u, unifont_glyph_header *out_header, const void **out_body, uint32_t ucs4) {
        unifont_glyph_header glyph_header = { };
        const void *glyph_body = NULL;
        const uint8_t *p;

        if (ucs4 >= u->n_glyphs)
                return -ENOENT;

        p = u->glyphs;

        /* copy glyph-header data */
        p += ucs4 * u->glyphsize;
        memcpy(&glyph_header, p, MIN(sizeof(glyph_header), u->header.glyph_header_size));

        /* copy glyph-body pointer */
        p += u->header.glyph_header_size;
        glyph_body = p;

        if (glyph_header.width < 1)
                return -ENOENT;
        if (glyph_header.width > u->header.glyph_stride)
                return -EBFONT;

        memcpy(out_header, &glyph_header, sizeof(glyph_header));
        *out_body = glyph_body;
        return 0;
}

int unifont_new(unifont **out) {
        _cleanup_(unifont_unrefp) unifont *u = NULL;
        struct stat st;
        int r;

        assert_return(out, -EINVAL);

        u = new0(unifont, 1);
        if (!u)
                return -ENOMEM;

        u->ref = 1;
        u->fd = -1;
        u->map = MAP_FAILED;

        u->fd = open(UNIFONT_PATH, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (u->fd < 0)
                return -errno;

        r = fstat(u->fd, &st);
        if (r < 0)
                return -errno;

        u->size = st.st_size;
        u->map = mmap(NULL, u->size, PROT_READ, MAP_PRIVATE, u->fd, 0);
        if (u->map == MAP_FAILED)
                return -errno;

        r = unifont_fetch_header(u);
        if (r < 0)
                return r;

        *out = u;
        u = NULL;
        return 0;
}

unifont *unifont_ref(unifont *u) {
        if (!u || !u->ref)
                return NULL;

        ++u->ref;

        return u;
}

unifont *unifont_unref(unifont *u) {
        if (!u || !u->ref || --u->ref)
                return NULL;

        if (u->map != MAP_FAILED)
                munmap((void*)u->map, u->size);
        u->fd = safe_close(u->fd);
        free(u);

        return NULL;
}

unsigned int unifont_get_width(unifont *u) {
        assert(u);

        return 8U;
}

unsigned int unifont_get_height(unifont *u) {
        assert(u);

        return 16U;
}

unsigned int unifont_get_stride(unifont *u) {
        assert(u);

        return u->header.glyph_stride;
}

int unifont_lookup(unifont *u, unifont_glyph *out, uint32_t ucs4) {
        unifont_glyph_header h = { };
        const void *b = NULL;
        unifont_glyph g = { };
        int r;

        assert_return(u, -EINVAL);

        r = unifont_fetch_glyph(u, &h, &b, ucs4);
        if (r < 0)
                return r;

        g.width = h.width * 8U;
        g.height = 16U;
        g.stride = u->header.glyph_stride;
        g.cwidth = h.width;
        g.data = b;

        if (out)
                memcpy(out, &g, sizeof(g));
        return 0;
}

void unifont_fallback(unifont_glyph *out) {
        static const uint8_t fallback_data[] = {
                /* unifont 0xfffd '�' (unicode replacement character) */
                0x00, 0x00, 0x00, 0x7e,
                0x66, 0x5a, 0x5a, 0x7a,
                0x76, 0x76, 0x7e, 0x76,
                0x76, 0x7e, 0x00, 0x00,
        };

        assert(out);

        out->width = 8;
        out->height = 16;
        out->stride = 1;
        out->cwidth = 1;
        out->data = fallback_data;
}
