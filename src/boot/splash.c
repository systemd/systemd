/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "graphics.h"
#include "logarithm.h"
#include "proto/graphics-output.h"
#include "splash.h"
#include "unaligned-fundamental.h"
#include "util.h"

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

static EFI_STATUS bmp_parse_header(
                const uint8_t *bmp,
                size_t size,
                struct bmp_dib **ret_dib,
                struct bmp_map **ret_map,
                const uint8_t **pixmap) {

        assert(bmp);
        assert(ret_dib);
        assert(ret_map);
        assert(pixmap);

        if (size < sizeof(struct bmp_file) + SIZEOF_BMP_DIB)
                return EFI_INVALID_PARAMETER;

        /* check file header */
        struct bmp_file *file = (struct bmp_file *) bmp;
        if (file->signature[0] != 'B' || file->signature[1] != 'M')
                return EFI_INVALID_PARAMETER;
        if (file->size != size)
                return EFI_INVALID_PARAMETER;
        if (file->size < file->offset)
                return EFI_INVALID_PARAMETER;

        /*  check device-independent bitmap */
        struct bmp_dib *dib = (struct bmp_dib *) (bmp + sizeof(struct bmp_file));
        if (dib->size < SIZEOF_BMP_DIB)
                return EFI_UNSUPPORTED;

        switch (dib->depth) {
        case 1:
        case 4:
        case 8:
        case 24:
                if (dib->compression != 0)
                        return EFI_UNSUPPORTED;

                break;

        case 16:
        case 32:
                if (!IN_SET(dib->compression, 0, 3))
                        return EFI_UNSUPPORTED;

                break;

        default:
                return EFI_UNSUPPORTED;
        }

        size_t row_size = ((size_t) dib->depth * dib->x + 31) / 32 * 4;
        if (file->size - file->offset <  dib->y * row_size)
                return EFI_INVALID_PARAMETER;
        if (row_size * dib->y > 64 * 1024 * 1024)
                return EFI_INVALID_PARAMETER;

        /* check color table */
        struct bmp_map *map = (struct bmp_map *) (bmp + sizeof(struct bmp_file) + dib->size);
        if (file->offset < sizeof(struct bmp_file) + dib->size)
                return EFI_INVALID_PARAMETER;

        if (file->offset > sizeof(struct bmp_file) + dib->size) {
                uint32_t map_count = 0;

                if (dib->colors_used)
                        map_count = dib->colors_used;
                else if (IN_SET(dib->depth, 1, 4, 8))
                        map_count = 1 << dib->depth;

                size_t map_size = file->offset - (sizeof(struct bmp_file) + dib->size);
                if (map_size != sizeof(struct bmp_map) * map_count)
                        return EFI_INVALID_PARAMETER;
        }

        *ret_map = map;
        *ret_dib = dib;
        *pixmap = bmp + file->offset;

        return EFI_SUCCESS;
}

enum Channels { R, G, B, A, _CHANNELS_MAX };
static void read_channel_maks(
                const struct bmp_dib *dib,
                uint32_t channel_mask[static _CHANNELS_MAX],
                uint8_t channel_shift[static _CHANNELS_MAX],
                uint8_t channel_scale[static _CHANNELS_MAX]) {

        assert(dib);

        if (IN_SET(dib->depth, 16, 32) && dib->size >= SIZEOF_BMP_DIB_RGB) {
                channel_mask[R] = dib->channel_mask_r;
                channel_mask[G] = dib->channel_mask_g;
                channel_mask[B] = dib->channel_mask_b;
                channel_shift[R] = __builtin_ctz(dib->channel_mask_r);
                channel_shift[G] = __builtin_ctz(dib->channel_mask_g);
                channel_shift[B] = __builtin_ctz(dib->channel_mask_b);
                channel_scale[R] = 0xff / ((1 << popcount(dib->channel_mask_r)) - 1);
                channel_scale[G] = 0xff / ((1 << popcount(dib->channel_mask_g)) - 1);
                channel_scale[B] = 0xff / ((1 << popcount(dib->channel_mask_b)) - 1);

                if (dib->size >= SIZEOF_BMP_DIB_RGBA && dib->channel_mask_a != 0) {
                        channel_mask[A] = dib->channel_mask_a;
                        channel_shift[A] = __builtin_ctz(dib->channel_mask_a);
                        channel_scale[A] = 0xff / ((1 << popcount(dib->channel_mask_a)) - 1);
                } else {
                        channel_mask[A] = 0;
                        channel_shift[A] = 0;
                        channel_scale[A] = 0;
                }
        } else {
                bool bpp16 = dib->depth == 16;
                channel_mask[R] = bpp16 ? 0x7C00 : 0xFF0000;
                channel_mask[G] = bpp16 ? 0x03E0 : 0x00FF00;
                channel_mask[B] = bpp16 ? 0x001F : 0x0000FF;
                channel_mask[A] = bpp16 ? 0x0000 : 0x000000;
                channel_shift[R] = bpp16 ? 0xA : 0x10;
                channel_shift[G] = bpp16 ? 0x5 : 0x08;
                channel_shift[B] = bpp16 ? 0x0 : 0x00;
                channel_shift[A] = bpp16 ? 0x0 : 0x00;
                channel_scale[R] = bpp16 ? 0x08 : 0x1;
                channel_scale[G] = bpp16 ? 0x08 : 0x1;
                channel_scale[B] = bpp16 ? 0x08 : 0x1;
                channel_scale[A] = bpp16 ? 0x00 : 0x0;
        }
}

static EFI_STATUS bmp_to_blt(
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL *buf,
                struct bmp_dib *dib,
                struct bmp_map *map,
                const uint8_t *pixmap) {

        const uint8_t *in;

        assert(buf);
        assert(dib);
        assert(map);
        assert(pixmap);

        uint32_t channel_mask[_CHANNELS_MAX];
        uint8_t channel_shift[_CHANNELS_MAX], channel_scale[_CHANNELS_MAX];
        read_channel_maks(dib, channel_mask, channel_shift, channel_scale);

        /* transform and copy pixels */
        in = pixmap;
        for (uint32_t y = 0; y < dib->y; y++) {
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL *out = &buf[(dib->y - y - 1) * dib->x];

                for (uint32_t x = 0; x < dib->x; x++, in++, out++) {
                        switch (dib->depth) {
                        case 1: {
                                for (unsigned i = 0; i < 8 && x < dib->x; i++) {
                                        out->Red = map[((*in) >> (7 - i)) & 1].red;
                                        out->Green = map[((*in) >> (7 - i)) & 1].green;
                                        out->Blue = map[((*in) >> (7 - i)) & 1].blue;
                                        out++;
                                        x++;
                                }
                                out--;
                                x--;
                                break;
                        }

                        case 4: {
                                unsigned i = (*in) >> 4;
                                out->Red = map[i].red;
                                out->Green = map[i].green;
                                out->Blue = map[i].blue;
                                if (x < (dib->x - 1)) {
                                        out++;
                                        x++;
                                        i = (*in) & 0x0f;
                                        out->Red = map[i].red;
                                        out->Green = map[i].green;
                                        out->Blue = map[i].blue;
                                }
                                break;
                        }

                        case 8:
                                out->Red = map[*in].red;
                                out->Green = map[*in].green;
                                out->Blue = map[*in].blue;
                                break;

                        case 24:
                                out->Red = in[2];
                                out->Green = in[1];
                                out->Blue = in[0];
                                in += 2;
                                break;

                        case 16:
                        case 32: {
                                uint32_t i = dib->depth == 16 ? unaligned_read_ne16(in) :
                                                                unaligned_read_ne32(in);

                                uint8_t r = ((i & channel_mask[R]) >> channel_shift[R]) * channel_scale[R],
                                        g = ((i & channel_mask[G]) >> channel_shift[G]) * channel_scale[G],
                                        b = ((i & channel_mask[B]) >> channel_shift[B]) * channel_scale[B],
                                        a = 0xFFu;
                                if (channel_mask[A] != 0)
                                        a = ((i & channel_mask[A]) >> channel_shift[A]) * channel_scale[A];

                                out->Red = (out->Red * (0xFFu - a) + r * a) >> 8;
                                out->Green = (out->Green * (0xFFu - a) + g * a) >> 8;
                                out->Blue = (out->Blue * (0xFFu - a) + b * a) >> 8;

                                in += dib->depth == 16 ? 1 : 3;
                                break;
                        }
                        }
                }

                /* add row padding; new lines always start at 32 bit boundary */
                size_t row_size = in - pixmap;
                in += ((row_size + 3) & ~3) - row_size;
        }

        return EFI_SUCCESS;
}

EFI_STATUS graphics_splash(const uint8_t *content, size_t len) {
        EFI_GRAPHICS_OUTPUT_BLT_PIXEL background = {};
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
        struct bmp_dib *dib;
        struct bmp_map *map;
        const uint8_t *pixmap;
        size_t x_pos = 0, y_pos = 0;
        EFI_STATUS err;

        if (len == 0)
                return EFI_SUCCESS;

        assert(content);

        if (strcaseeq16(ST->FirmwareVendor, u"Apple")) {
                background.Red = 0xc0;
                background.Green = 0xc0;
                background.Blue = 0xc0;
        }

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_GRAPHICS_OUTPUT_PROTOCOL), NULL, (void **) &GraphicsOutput);
        if (err != EFI_SUCCESS)
                return err;

        err = bmp_parse_header(content, len, &dib, &map, &pixmap);
        if (err != EFI_SUCCESS)
                return err;

        if (dib->x < GraphicsOutput->Mode->Info->HorizontalResolution)
                x_pos = (GraphicsOutput->Mode->Info->HorizontalResolution - dib->x) / 2;
        if (dib->y < GraphicsOutput->Mode->Info->VerticalResolution)
                y_pos = (GraphicsOutput->Mode->Info->VerticalResolution - dib->y) / 2;

        err = GraphicsOutput->Blt(
                        GraphicsOutput, &background,
                        EfiBltVideoFill, 0, 0, 0, 0,
                        GraphicsOutput->Mode->Info->HorizontalResolution,
                        GraphicsOutput->Mode->Info->VerticalResolution, 0);
        if (err != EFI_SUCCESS)
                return err;

        /* Read in current screen content to perform proper alpha blending. */
        _cleanup_free_ EFI_GRAPHICS_OUTPUT_BLT_PIXEL *blt = xnew(
                        EFI_GRAPHICS_OUTPUT_BLT_PIXEL, dib->x * dib->y);
        err = GraphicsOutput->Blt(
                        GraphicsOutput, blt,
                        EfiBltVideoToBltBuffer, x_pos, y_pos, 0, 0,
                        dib->x, dib->y, 0);
        if (err != EFI_SUCCESS)
                return err;

        err = bmp_to_blt(blt, dib, map, pixmap);
        if (err != EFI_SUCCESS)
                return err;

        err = graphics_mode(true);
        if (err != EFI_SUCCESS)
                return err;

        return GraphicsOutput->Blt(
                        GraphicsOutput, blt,
                        EfiBltBufferToVideo, 0, 0, x_pos, y_pos,
                        dib->x, dib->y, 0);
}
