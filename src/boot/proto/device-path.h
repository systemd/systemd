/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_DEVICE_PATH_PROTOCOL_GUID \
        GUID_DEF(0x09576e91, 0x6d3f, 0x11d2, 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)
#define EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID \
        GUID_DEF(0x8b843e20, 0x8132, 0x4852, 0x90, 0xcc, 0x55, 0x1a, 0x4e, 0x4a, 0x7f, 0x1c)
#define EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL_GUID \
        GUID_DEF(0x05c99a21, 0xc70f, 0x4ad2, 0x8a, 0x5f, 0x35, 0xdf, 0x33, 0x43, 0xf5, 0x1e)

/* Device path types. */
enum {
        HARDWARE_DEVICE_PATH  = 0x01,
        ACPI_DEVICE_PATH      = 0x02,
        MESSAGING_DEVICE_PATH = 0x03,
        MEDIA_DEVICE_PATH     = 0x04,
        BBS_DEVICE_PATH       = 0x05,
        END_DEVICE_PATH_TYPE  = 0x7f,
};

/* Device path sub-types. */
enum {
        END_INSTANCE_DEVICE_PATH_SUBTYPE = 0x01,
        END_ENTIRE_DEVICE_PATH_SUBTYPE   = 0xff,

        MEDIA_HARDDRIVE_DP               = 0x01,
        MEDIA_VENDOR_DP                  = 0x03,
        MEDIA_FILEPATH_DP                = 0x04,
        MEDIA_PIWG_FW_FILE_DP            = 0x06,
        MEDIA_PIWG_FW_VOL_DP             = 0x07,
};

struct _packed_ EFI_DEVICE_PATH_PROTOCOL {
        uint8_t Type;
        uint8_t SubType;
        uint16_t Length;
};

typedef struct {
        EFI_DEVICE_PATH Header;
        EFI_GUID Guid;
} _packed_ VENDOR_DEVICE_PATH;

#define MBR_TYPE_PCAT                        0x01U
#define MBR_TYPE_EFI_PARTITION_TABLE_HEADER  0x02U
#define NO_DISK_SIGNATURE    0x00U
#define SIGNATURE_TYPE_MBR   0x01U
#define SIGNATURE_TYPE_GUID  0x02U

typedef struct {
        EFI_DEVICE_PATH Header;
        uint32_t PartitionNumber;
        uint64_t PartitionStart;
        uint64_t PartitionSize;
        union {
                uint8_t Signature[16];
                EFI_GUID SignatureGuid;
        };
        uint8_t MBRType;
        uint8_t SignatureType;
} _packed_ HARDDRIVE_DEVICE_PATH;

typedef struct {
        EFI_DEVICE_PATH Header;
        char16_t PathName[];
} _packed_ FILEPATH_DEVICE_PATH;

typedef struct {
        char16_t* (EFIAPI *ConvertDeviceNodeToText)(
                        const EFI_DEVICE_PATH *DeviceNode,
                        bool DisplayOnly,
                        bool AllowShortcuts);
        char16_t* (EFIAPI *ConvertDevicePathToText)(
                        const EFI_DEVICE_PATH *DevicePath,
                        bool DisplayOnly,
                        bool AllowShortcuts);
} EFI_DEVICE_PATH_TO_TEXT_PROTOCOL;

typedef struct {
        EFI_DEVICE_PATH* (EFIAPI *ConvertTextToDevicNode)(
                        const char16_t *TextDeviceNode);
        EFI_DEVICE_PATH* (EFIAPI *ConvertTextToDevicPath)(
                        const char16_t *ConvertTextToDevicPath);
} EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL;
