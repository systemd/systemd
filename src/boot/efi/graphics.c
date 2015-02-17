/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Copyright (C) 2012-2013 Kay Sievers <kay@vrfy.org>
 * Copyright (C) 2012 Harald Hoyer <harald@redhat.com>
 * Copyright (C) 2013 Intel Corporation
 *   Authored by Joonas Lahtinen <joonas.lahtinen@linux.intel.com>
 */

#include <efi.h>
#include <efilib.h>

#include "util.h"
#include "graphics.h"

EFI_STATUS graphics_mode(BOOLEAN on) {
        #define EFI_CONSOLE_CONTROL_PROTOCOL_GUID \
                { 0xf42f7782, 0x12e, 0x4c12, { 0x99, 0x56, 0x49, 0xf9, 0x43, 0x4, 0xf7, 0x21 } };

        struct _EFI_CONSOLE_CONTROL_PROTOCOL;

        typedef enum {
                EfiConsoleControlScreenText,
                EfiConsoleControlScreenGraphics,
                EfiConsoleControlScreenMaxValue,
        } EFI_CONSOLE_CONTROL_SCREEN_MODE;

        typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE)(
                struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
                EFI_CONSOLE_CONTROL_SCREEN_MODE *Mode,
                BOOLEAN *UgaExists,
                BOOLEAN *StdInLocked
        );

        typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE)(
                struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
                EFI_CONSOLE_CONTROL_SCREEN_MODE Mode
        );

        typedef EFI_STATUS (EFIAPI *EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN)(
                struct _EFI_CONSOLE_CONTROL_PROTOCOL *This,
                CHAR16 *Password
        );

        typedef struct _EFI_CONSOLE_CONTROL_PROTOCOL {
                EFI_CONSOLE_CONTROL_PROTOCOL_GET_MODE GetMode;
                EFI_CONSOLE_CONTROL_PROTOCOL_SET_MODE SetMode;
                EFI_CONSOLE_CONTROL_PROTOCOL_LOCK_STD_IN LockStdIn;
        } EFI_CONSOLE_CONTROL_PROTOCOL;

        EFI_GUID ConsoleControlProtocolGuid = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;
        EFI_CONSOLE_CONTROL_PROTOCOL *ConsoleControl = NULL;
        EFI_CONSOLE_CONTROL_SCREEN_MODE new;
        EFI_CONSOLE_CONTROL_SCREEN_MODE current;
        BOOLEAN uga_exists;
        BOOLEAN stdin_locked;
        EFI_STATUS err;

        err = LibLocateProtocol(&ConsoleControlProtocolGuid, (VOID **)&ConsoleControl);
        if (EFI_ERROR(err)) {
                /* console control protocol is nonstandard and might not exist. */
                return err == EFI_NOT_FOUND ? EFI_SUCCESS : err;
        }

        /* check current mode */
        err = uefi_call_wrapper(ConsoleControl->GetMode, 4, ConsoleControl, &current, &uga_exists, &stdin_locked);
        if (EFI_ERROR(err))
                return err;

        /* do not touch the mode */
        new  = on ? EfiConsoleControlScreenGraphics : EfiConsoleControlScreenText;
        if (new == current)
                return EFI_SUCCESS;

        err = uefi_call_wrapper(ConsoleControl->SetMode, 2, ConsoleControl, new);

        /* some firmware enables the cursor when switching modes */
        uefi_call_wrapper(ST->ConOut->EnableCursor, 2, ST->ConOut, FALSE);

        return err;
}

struct bmp_file {
        CHAR8 signature[2];
        UINT32 size;
        UINT16 reserved[2];
        UINT32 offset;
} __attribute__((packed));

/* we require at least BITMAPINFOHEADER, later versions are
   accepted, but their features ignored */
struct bmp_dib {
        UINT32 size;
        UINT32 x;
        UINT32 y;
        UINT16 planes;
        UINT16 depth;
        UINT32 compression;
        UINT32 image_size;
        INT32 x_pixel_meter;
        INT32 y_pixel_meter;
        UINT32 colors_used;
        UINT32 colors_important;
} __attribute__((packed));

struct bmp_map {
        UINT8 blue;
        UINT8 green;
        UINT8 red;
        UINT8 reserved;
} __attribute__((packed));

EFI_STATUS bmp_parse_header(UINT8 *bmp, UINTN size, struct bmp_dib **ret_dib,
                            struct bmp_map **ret_map, UINT8 **pixmap) {
        struct bmp_file *file;
        struct bmp_dib *dib;
        struct bmp_map *map;
        UINTN row_size;

        if (size < sizeof(struct bmp_file) + sizeof(struct bmp_dib))
                return EFI_INVALID_PARAMETER;

        /* check file header */
        file = (struct bmp_file *)bmp;
        if (file->signature[0] != 'B' || file->signature[1] != 'M')
                return EFI_INVALID_PARAMETER;
        if (file->size != size)
                return EFI_INVALID_PARAMETER;
        if (file->size < file->offset)
                return EFI_INVALID_PARAMETER;

        /*  check device-independent bitmap */
        dib = (struct bmp_dib *)(bmp + sizeof(struct bmp_file));
        if (dib->size < sizeof(struct bmp_dib))
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
                if (dib->compression != 0 && dib->compression != 3)
                        return EFI_UNSUPPORTED;

                break;

        default:
                return EFI_UNSUPPORTED;
        }

        row_size = (((dib->depth * dib->x) + 31) / 32) * 4;
        if (file->size - file->offset <  dib->y * row_size)
                return EFI_INVALID_PARAMETER;
        if (row_size * dib->y > 64 * 1024 * 1024)
                return EFI_INVALID_PARAMETER;

        /* check color table */
        map = (struct bmp_map *)(bmp + sizeof(struct bmp_file) + dib->size);
        if (file->offset < sizeof(struct bmp_file) + dib->size)
                return EFI_INVALID_PARAMETER;

        if (file->offset > sizeof(struct bmp_file) + dib->size) {
                UINT32 map_count;
                UINTN map_size;

                if (dib->colors_used)
                        map_count = dib->colors_used;
                else {
                        switch (dib->depth) {
                        case 1:
                        case 4:
                        case 8:
                                map_count = 1 << dib->depth;
                                break;

                        default:
                                map_count = 0;
                                break;
                        }
                }

                map_size = file->offset - (sizeof(struct bmp_file) + dib->size);
                if (map_size != sizeof(struct bmp_map) * map_count)
                        return EFI_INVALID_PARAMETER;
        }

        *ret_map = map;
        *ret_dib = dib;
        *pixmap = bmp + file->offset;

        return EFI_SUCCESS;
}

static VOID pixel_blend(UINT32 *dst, const UINT32 source) {
        UINT32 alpha, src, src_rb, src_g, dst_rb, dst_g, rb, g;

        alpha = (source & 0xff);

        /* convert src from RGBA to XRGB */
        src = source >> 8;

        /* decompose into RB and G components */
        src_rb = (src & 0xff00ff);
        src_g  = (src & 0x00ff00);

        dst_rb = (*dst & 0xff00ff);
        dst_g  = (*dst & 0x00ff00);

        /* blend */
        rb = ((((src_rb - dst_rb) * alpha + 0x800080) >> 8) + dst_rb) & 0xff00ff;
        g  = ((((src_g  -  dst_g) * alpha + 0x008000) >> 8) +  dst_g) & 0x00ff00;

        *dst = (rb | g);
}

EFI_STATUS bmp_to_blt(EFI_GRAPHICS_OUTPUT_BLT_PIXEL *buf,
                      struct bmp_dib *dib, struct bmp_map *map,
                      UINT8 *pixmap) {
        UINT8 *in;
        UINTN y;

        /* transform and copy pixels */
        in = pixmap;
        for (y = 0; y < dib->y; y++) {
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL *out;
                UINTN row_size;
                UINTN x;

                out = &buf[(dib->y - y - 1) * dib->x];
                for (x = 0; x < dib->x; x++, in++, out++) {
                        switch (dib->depth) {
                        case 1: {
                                UINTN i;

                                for (i = 0; i < 8 && x < dib->x; i++) {
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
                                UINTN i;

                                i = (*in) >> 4;
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

                        case 16: {
                                UINT16 i = *(UINT16 *) in;

                                out->Red = (i & 0x7c00) >> 7;
                                out->Green = (i & 0x3e0) >> 2;
                                out->Blue = (i & 0x1f) << 3;
                                in += 1;
                                break;
                        }

                        case 24:
                                out->Red = in[2];
                                out->Green = in[1];
                                out->Blue = in[0];
                                in += 2;
                                break;

                        case 32: {
                                UINT32 i = *(UINT32 *) in;

                                pixel_blend((UINT32 *)out, i);

                                in += 3;
                                break;
                        }
                        }
                }

                /* add row padding; new lines always start at 32 bit boundary */
                row_size = in - pixmap;
                in += ((row_size + 3) & ~3) - row_size;
        }

        return EFI_SUCCESS;
}

EFI_STATUS graphics_splash(EFI_FILE *root_dir, CHAR16 *path,
                           const EFI_GRAPHICS_OUTPUT_BLT_PIXEL *background) {
        EFI_GUID GraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
        EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
        UINT8 *content;
        INTN len;
        struct bmp_dib *dib;
        struct bmp_map *map;
        UINT8 *pixmap;
        UINT64 blt_size;
        VOID *blt = NULL;
        UINTN x_pos = 0;
        UINTN y_pos = 0;
        EFI_STATUS err;

        err = LibLocateProtocol(&GraphicsOutputProtocolGuid, (VOID **)&GraphicsOutput);
        if (EFI_ERROR(err))
                return err;

        len = file_read(root_dir, path, 0, 0, &content);
        if (len < 0)
                return EFI_LOAD_ERROR;

        err = bmp_parse_header(content, len, &dib, &map, &pixmap);
        if (EFI_ERROR(err))
                goto err;

        if(dib->x < GraphicsOutput->Mode->Info->HorizontalResolution)
                x_pos = (GraphicsOutput->Mode->Info->HorizontalResolution - dib->x) / 2;
        if(dib->y < GraphicsOutput->Mode->Info->VerticalResolution)
                y_pos = (GraphicsOutput->Mode->Info->VerticalResolution - dib->y) / 2;

        uefi_call_wrapper(GraphicsOutput->Blt, 10, GraphicsOutput,
                          (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)background,
                          EfiBltVideoFill, 0, 0, 0, 0,
                          GraphicsOutput->Mode->Info->HorizontalResolution,
                          GraphicsOutput->Mode->Info->VerticalResolution, 0);

        /* EFI buffer */
        blt_size = dib->x * dib->y * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
        blt = AllocatePool(blt_size);
        if (!blt)
                return EFI_OUT_OF_RESOURCES;

        err = uefi_call_wrapper(GraphicsOutput->Blt, 10, GraphicsOutput,
                                blt, EfiBltVideoToBltBuffer, x_pos, y_pos, 0, 0,
                                dib->x, dib->y, 0);
        if (EFI_ERROR(err))
                goto err;

        err = bmp_to_blt(blt, dib, map, pixmap);
        if (EFI_ERROR(err))
                goto err;

        err = graphics_mode(TRUE);
        if (EFI_ERROR(err))
                goto err;

        err = uefi_call_wrapper(GraphicsOutput->Blt, 10, GraphicsOutput,
                                blt, EfiBltBufferToVideo, 0, 0, x_pos, y_pos,
                                dib->x, dib->y, 0);
err:
        FreePool(blt);
        FreePool(content);
        return err;
}
