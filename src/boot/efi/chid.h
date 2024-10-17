/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include "efi.h"

#include "chid-fundamental.h"

typedef struct Device {
        uint32_t struct_size;       /* = sizeof(struct Device), or 0 for EOL */
        uint32_t name_offset;       /* nul-terminated string or 0 if not present */
        uint32_t compatible_offset; /* nul-terminated string or 0 if not present */
        EFI_GUID chid;
} _packed_ Device;

static inline const char* device_get_name(const void *base, const Device *device) {
        return device->name_offset == 0 ? NULL : (const char *) ((const uint8_t *) base + device->name_offset);
}

static inline const char* device_get_compatible(const void *base, const Device *device) {
        return device->compatible_offset == 0 ? NULL : (const char *) ((const uint8_t *) base + device->compatible_offset);
}

EFI_STATUS chid_match(const void *chids_buffer, size_t chids_length, const Device **ret_device);
