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

#pragma once

#include <stdint.h>

typedef struct unifont unifont;
typedef struct unifont_glyph unifont_glyph;

/*
 * Unifont
 * The unifont API provides a glyph-lookup for bitmap fonts which can be used
 * as fallback if no system-font is available or if you don't want to deal with
 * full font renderers.
 */

struct unifont_glyph {
        unsigned int width;
        unsigned int height;
        unsigned int stride;
        unsigned int cwidth;
        const void *data;       /* unaligned! */
};

int unifont_new(unifont **out);
unifont *unifont_ref(unifont *u);
unifont *unifont_unref(unifont *u);

DEFINE_TRIVIAL_CLEANUP_FUNC(unifont*, unifont_unref);

unsigned int unifont_get_width(unifont *u);
unsigned int unifont_get_height(unifont *u);
unsigned int unifont_get_stride(unifont *u);
int unifont_lookup(unifont *u, unifont_glyph *out, uint32_t ucs4);
void unifont_fallback(unifont_glyph *out);
