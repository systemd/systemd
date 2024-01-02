/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-id128.h"

typedef struct KernelHibernateLocation KernelHibernateLocation;
typedef struct EFIHibernateLocation EFIHibernateLocation;

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

#else

static inline void compare_hibernate_location_and_warn(const HibernateInfo *info) {
        return;
}

#endif
