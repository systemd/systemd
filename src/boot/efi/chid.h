/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include "efi.h"

#include "chid-fundamental.h"

typedef struct Device {
        char name[128];        /* Arbitrary size, shoule be big enough to fit any device name */
        char compatible[128];  /* Linux kernel limit compatible to 128 characters */
        WindowsGuid chids[32]; /* Arbitrary size, should be at least 15 to fit all IDs from `fwupdtool hwids` */
} Device;

static_assert(sizeof(WindowsGuid) == sizeof(EFI_GUID));

EFI_STATUS chid_match(const void *chids_buffer, size_t chids_length, const Device **ret_device);
