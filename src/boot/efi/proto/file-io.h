/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
        GUID_DEF(0x0964e5b22, 0x6459, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
#define EFI_FILE_INFO_ID \
        GUID_DEF(0x009576e92, 0x6d3f, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_FILE_MODE_READ   0x0000000000000001U
#define EFI_FILE_MODE_WRITE  0x0000000000000002U
#define EFI_FILE_MODE_CREATE 0x8000000000000000U

#define EFI_FILE_READ_ONLY  0x01U
#define EFI_FILE_HIDDEN     0x02U
#define EFI_FILE_SYSTEM     0x04U
#define EFI_FILE_RESERVED   0x08U
#define EFI_FILE_DIRECTORY  0x10U
#define EFI_FILE_ARCHIVE    0x20U
#define EFI_FILE_VALID_ATTR 0x37U

typedef struct {
        uint64_t Size;
        uint64_t FileSize;
        uint64_t PhysicalSize;
        EFI_TIME CreateTime;
        EFI_TIME LastAccessTime;
        EFI_TIME ModificationTime;
        uint64_t Attribute;
        char16_t FileName[];
} EFI_FILE_INFO;

/* Some broken firmware violates the EFI spec by still advancing the readdir
 * position when returning EFI_BUFFER_TOO_SMALL, effectively skipping over any files when
 * the buffer was too small. Therefore, we always start with a buffer that should handle FAT32
 * max file name length. */
#define EFI_FILE_INFO_MIN_SIZE (offsetof(EFI_FILE_INFO, FileName) + 256U * sizeof(char16_t))

typedef struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
        uint64_t Revision;
        EFI_STATUS (EFIAPI *OpenVolume)(
                        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This,
                        EFI_FILE **Root);
};

struct EFI_FILE_PROTOCOL {
        uint64_t Revision;
        EFI_STATUS (EFIAPI *Open)(
                        EFI_FILE *This,
                        EFI_FILE **NewHandle,
                        char16_t *FileName,
                        uint64_t OpenMode,
                        uint64_t Attributes);
        EFI_STATUS (EFIAPI *Close)(EFI_FILE *This);
        EFI_STATUS (EFIAPI *Delete)(EFI_FILE *This);
        EFI_STATUS (EFIAPI *Read)(
                        EFI_FILE *This,
                        size_t *BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *Write)(
                        EFI_FILE *This,
                        size_t *BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *GetPosition)(EFI_FILE *This, uint64_t *Position);
        EFI_STATUS (EFIAPI *SetPosition)(EFI_FILE *This, uint64_t Position);
        EFI_STATUS (EFIAPI *GetInfo)(
                        EFI_FILE *This,
                        EFI_GUID *InformationType,
                        size_t *BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *SetInfo)(
                        EFI_FILE *This,
                        EFI_GUID *InformationType,
                        size_t BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *Flush)(EFI_FILE *This);
        void *OpenEx;
        void *ReadEx;
        void *WriteEx;
        void *FlushEx;
};
