/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include "efi.h"
#include "chid-fundamental.h"

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

static inline const char* device_get_name(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_DEVICETREE:
                off = device->devicetree.name_offset;
                break;
        case DEVICE_TYPE_UEFI_FW:
                off = device->uefi_fw.name_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

static inline const char* device_get_compatible(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_DEVICETREE:
                off = device->devicetree.compatible_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

static inline const char* device_get_fwid(const void *base, const Device *device) {
        size_t off = 0;
        switch (DEVICE_TYPE_FROM_DESCRIPTOR(device->descriptor)) {
        case DEVICE_TYPE_UEFI_FW:
                off = device->uefi_fw.fwid_offset;
                break;
        default:
                return NULL;
        }
        return off == 0 ? NULL : (const char *) ((const uint8_t *) base + off);
}

EFI_STATUS chid_match(const void *chids_buffer, size_t chids_length, uint32_t match_type, const Device **ret_device);
