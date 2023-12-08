/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

typedef struct KernelHibernateLocation {
        char *device;
        uint64_t offset;
        bool offset_set;
} KernelHibernateLocation;

typedef struct EFIHibernateLocation {
        char *device;

        sd_id128_t uuid;
        uint64_t offset;

        char *kernel_version;
        char *id;
        char *image_id;
        char *version_id;
        char *image_version;
} EFIHibernateLocation;

typedef struct HibernateInfo {
        const char *device;
        uint64_t offset; /* in memory pages */

        KernelHibernateLocation *cmdline;
        EFIHibernateLocation *efi;
} HibernateInfo;

void hibernate_info_done(HibernateInfo *info);

int acquire_hibernate_info(HibernateInfo *ret);

#if ENABLE_EFI

void compare_hibernate_location_and_warn(const HibernateInfo *info);

void clear_efi_hibernate_location(void);

#else

static inline void compare_hibernate_location_and_warn(const HibernateInfo *info) {
        return;
}

static inline void clear_efi_hibernate_location(void) {
        return;
}

#endif
