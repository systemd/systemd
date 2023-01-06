/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_BLOCK_IO_PROTOCOL_GUID \
        GUID_DEF(0x0964e5b21, 0x6459, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

typedef struct EFI_BLOCK_IO_PROTOCOL EFI_BLOCK_IO_PROTOCOL;
struct EFI_BLOCK_IO_PROTOCOL {
        uint64_t Revision;
        struct {
                uint32_t MediaId;
                bool RemovableMedia;
                bool MediaPresent;
                bool LogicalPartition;
                bool ReadOnly;
                bool WriteCaching;
                uint32_t BlockSize;
                uint32_t IoAlign;
                EFI_LBA LastBlock;
                EFI_LBA LowestAlignedLba;
                uint32_t LogicalBlocksPerPhysicalBlock;
                uint32_t OptimalTransferLengthGranularity;
        } *Media;

        EFI_STATUS (EFIAPI *Reset)(
                        EFI_BLOCK_IO_PROTOCOL *This,
                        bool ExtendedVerification);
        EFI_STATUS (EFIAPI *ReadBlocks)(
                        EFI_BLOCK_IO_PROTOCOL *This,
                        uint32_t MediaId,
                        EFI_LBA LBA,
                        size_t BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *WriteBlocks)(
                        EFI_BLOCK_IO_PROTOCOL *This,
                        uint32_t MediaId,
                        EFI_LBA LBA,
                        size_t BufferSize,
                        void *Buffer);
        EFI_STATUS (EFIAPI *FlushBlocks)(EFI_BLOCK_IO_PROTOCOL *This);
};
