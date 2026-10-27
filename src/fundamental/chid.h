/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include "efi.h"
#include "macro.h"

#if !SD_BOOT
#  include <uchar.h>
#endif

#define CHID_TYPES_MAX 18
/* Any chids starting from EXTRA_CHID_BASE are non-standard and are subject to change and renumeration at any time */
#define EXTRA_CHID_BASE 15

typedef enum ChidSmbiosFields {
        CHID_SMBIOS_MANUFACTURER,
        CHID_SMBIOS_FAMILY,
        CHID_SMBIOS_PRODUCT_NAME,
        CHID_SMBIOS_PRODUCT_SKU,
        CHID_SMBIOS_BASEBOARD_MANUFACTURER,
        CHID_SMBIOS_BASEBOARD_PRODUCT,
        CHID_SMBIOS_BIOS_VENDOR,
        CHID_SMBIOS_BIOS_VERSION,
        CHID_SMBIOS_BIOS_MAJOR,
        CHID_SMBIOS_BIOS_MINOR,
        CHID_SMBIOS_ENCLOSURE_TYPE,
        CHID_EDID_PANEL,
        _CHID_SMBIOS_FIELDS_MAX,
} ChidSmbiosFields;

extern const uint32_t chid_smbios_table[CHID_TYPES_MAX];

/* CHID (also called HWID by fwupd) is described at https://github.com/fwupd/fwupd/blob/main/docs/hwids.md */
void chid_calculate(const char16_t *const smbios_fields[static _CHID_SMBIOS_FIELDS_MAX], EFI_GUID ret_chids[static CHID_TYPES_MAX]);

/* A .hwids PE section consists of a series of 'Device' structures. A 'Device' structure binds a CHID to some
 * resource, for now only Devicetree blobs. Designed to be extensible to other types of resources, should the
 * need arise. The series of 'Device' structures is followed by some space for strings that can be referenced
 * by offset by the Device structures. */

enum {
        DEVICE_TYPE_DEVICETREE = 0x1, /* A devicetree blob */
        DEVICE_TYPE_UEFI_FW    = 0x2, /* A firmware blob */

        /* Maybe later additional types for:
         *   - CoCo Bring-Your-Own-Firmware
         *   - ACPI DSDT Overrides
         *   - … */
        _DEVICE_TYPE_MAX,
};

#define DEVICE_SIZE_FROM_DESCRIPTOR(u) ((uint32_t) (u) & UINT32_C(0x0FFFFFFF))
#define DEVICE_TYPE_FROM_DESCRIPTOR(u) ((uint32_t) (u) >> 28)
#define DEVICE_MAKE_DESCRIPTOR(type, size) (((uint32_t) (size) | ((uint32_t) type << 28)))

#define DEVICE_DESCRIPTOR_DEVICETREE DEVICE_MAKE_DESCRIPTOR(DEVICE_TYPE_DEVICETREE, sizeof(Device))
#define DEVICE_DESCRIPTOR_UEFI_FW DEVICE_MAKE_DESCRIPTOR(DEVICE_TYPE_UEFI_FW, sizeof(Device))
#define DEVICE_DESCRIPTOR_EOL UINT32_C(0)

typedef struct Device {
        uint32_t descriptor; /* The highest four bit encode the type of entry, the other 28 bit encode the
                              * size of the structure. Use the macros above to generate or take apart this
                              * field. */
        EFI_GUID chid;
        union {
                struct {
                        /* These offsets are relative to the beginning of the .hwids PE section. */
                        uint32_t name_offset;          /* nul-terminated string or 0 if not present */
                        uint32_t compatible_offset;    /* nul-terminated string or 0 if not present */
                } devicetree;
                struct {
                        /* Offsets are relative to the beginning of the .hwids PE section.
                         * They are nul-terminated strings when present or 0 if not present */
                        uint32_t name_offset;       /* name or identifier for the firmware blob */
                        uint32_t fwid_offset;       /* identifier to match a specific uefi firmware blob */
                } uefi_fw;

                /* fields for other descriptor types… */
        };
} _packed_ Device;

/* Validate some offset, since the structure is API and src/ukify/ukify.py encodes them directly */
assert_cc(offsetof(Device, descriptor) == 0);
assert_cc(offsetof(Device, chid) == 4);
assert_cc(offsetof(Device, devicetree.name_offset) == 20);
assert_cc(offsetof(Device, devicetree.compatible_offset) == 24);
assert_cc(offsetof(Device, uefi_fw.name_offset) == 20);
assert_cc(offsetof(Device, uefi_fw.fwid_offset) == 24);
assert_cc(sizeof(Device) == 28);
