/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !SD_BOOT
#  include <stddef.h>
#  include <stdint.h>
#endif

#include "macro.h"

struct bmp_file {
        char signature[2];
        uint32_t size;
        uint16_t reserved[2];
        uint32_t offset;
} _packed_;

/* we require at least BITMAPINFOHEADER, later versions are
   accepted, but their features ignored */
struct bmp_dib {
        uint32_t size;
        uint32_t x;
        uint32_t y;
        uint16_t planes;
        uint16_t depth;
        uint32_t compression;
        uint32_t image_size;
        int32_t x_pixel_meter;
        int32_t y_pixel_meter;
        uint32_t colors_used;
        uint32_t colors_important;
        uint32_t channel_mask_r;
        uint32_t channel_mask_g;
        uint32_t channel_mask_b;
        uint32_t channel_mask_a;
} _packed_;

#define SIZEOF_BMP_DIB offsetof(struct bmp_dib, channel_mask_r)
#define SIZEOF_BMP_DIB_RGB offsetof(struct bmp_dib, channel_mask_a)
#define SIZEOF_BMP_DIB_RGBA sizeof(struct bmp_dib)

struct bmp_map {
        uint8_t blue;
        uint8_t green;
        uint8_t red;
        uint8_t reserved;
} _packed_;

int bmp_parse_header(
                const uint8_t *bmp,
                size_t size,
                const struct bmp_dib **ret_dib,
                const struct bmp_map **ret_map,
                const uint8_t **ret_pixmap);
