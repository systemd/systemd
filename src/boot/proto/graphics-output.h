/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID \
        GUID_DEF(0x9042a9de, 0x23dc, 0x4a38, 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a)

typedef enum {
        PixelRedGreenBlueReserved8BitPerColor,
        PixelBlueGreenRedReserved8BitPerColor,
        PixelBitMask,
        PixelBltOnly,
        PixelFormatMax,
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef enum {
        EfiBltVideoFill,
        EfiBltVideoToBltBuffer,
        EfiBltBufferToVideo,
        EfiBltVideoToVideo,
        EfiGraphicsOutputBltOperationMax,
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

typedef struct {
        uint32_t RedMask;
        uint32_t GreenMask;
        uint32_t BlueMask;
        uint32_t ReservedMask;
} EFI_PIXEL_BITMASK;

typedef struct {
        uint8_t Blue;
        uint8_t Green;
        uint8_t Red;
        uint8_t Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef struct {
        uint32_t Version;
        uint32_t HorizontalResolution;
        uint32_t VerticalResolution;
        EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
        EFI_PIXEL_BITMASK PixelInformation;
        uint32_t PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct EFI_GRAPHICS_OUTPUT_PROTOCOL EFI_GRAPHICS_OUTPUT_PROTOCOL;
struct EFI_GRAPHICS_OUTPUT_PROTOCOL {
        EFI_STATUS (EFIAPI *QueryMode)(
                        EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                        uint32_t ModeNumber,
                        size_t *SizeOfInfo,
                        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info);
        EFI_STATUS(EFIAPI *SetMode)(
                        EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                        uint32_t ModeNumber);
        EFI_STATUS (EFIAPI *Blt)(
                        EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                        EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer,
                        EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation,
                        size_t SourceX,
                        size_t SourceY,
                        size_t DestinationX,
                        size_t DestinationY,
                        size_t Width,
                        size_t Height,
                        size_t Delta);

        struct {
                uint32_t MaxMode;
                uint32_t Mode;
                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
                size_t SizeOfInfo;
                EFI_PHYSICAL_ADDRESS FrameBufferBase;
                size_t FrameBufferSize;
        } *Mode;
};
