/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_PCI_IO_PROTOCOL_GUID \
        GUID_DEF(0x4cf5b200, 0x68b8, 0x4ca5, 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a)

typedef enum {
        EfiPciIoWidthUint8,
        EfiPciIoWidthUint16,
        EfiPciIoWidthUint32,
        EfiPciIoWidthUint64,
} EFI_PCI_IO_PROTOCOL_WIDTH;

typedef struct EFI_PCI_IO_PROTOCOL EFI_PCI_IO_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_PCI_IO_PROTOCOL_CONFIG)(
                EFI_PCI_IO_PROTOCOL *This,
                EFI_PCI_IO_PROTOCOL_WIDTH Width,
                uint32_t Offset,
                size_t Count,
                void *Buffer);

typedef struct {
        EFI_PCI_IO_PROTOCOL_CONFIG Read;
        EFI_PCI_IO_PROTOCOL_CONFIG Write;
} EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS;

/* Minimal definition — only Pci.Read is used. Fields before Pci must be correctly sized
 * (one function pointer each for PollMem/PollIo, two for Mem.Read/Write, two for Io.Read/Write)
 * to ensure Pci is at the right offset. */
struct EFI_PCI_IO_PROTOCOL {
        void *PollMem;
        void *PollIo;
        EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS Mem;
        EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS Io;
        EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS Pci;
        /* remaining fields omitted */
};

#define PCI_VENDOR_ID_REDHAT         0x1af4U
#define PCI_DEVICE_ID_VIRTIO_CONSOLE 0x1003U
