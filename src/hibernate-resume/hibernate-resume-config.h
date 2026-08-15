/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "forward.h"

typedef struct KernelHibernateLocation KernelHibernateLocation;

typedef struct EFIHibernateLocation {
        char *device;

        sd_id128_t uuid;
        uint64_t offset;

        /* Whether the device we hibernated into is the "auto" one, i.e. will show up as
         * /dev/disk/by-designator/swap(-luks). */
        bool auto_swap;

        char *kernel_version;
        char *id;
        char *image_id;
        char *version_id;
        char *image_version;
} EFIHibernateLocation;

EFIHibernateLocation* efi_hibernate_location_free(EFIHibernateLocation *e);
DEFINE_TRIVIAL_CLEANUP_FUNC(EFIHibernateLocation*, efi_hibernate_location_free);

int get_efi_hibernate_location(EFIHibernateLocation **ret);

typedef struct HibernateInfo {
        const char *device;
        uint64_t offset; /* in memory pages */

        KernelHibernateLocation *cmdline;
        EFIHibernateLocation *efi;
} HibernateInfo;

void hibernate_info_done(HibernateInfo *info);

int acquire_hibernate_info(HibernateInfo *ret);

void compare_hibernate_location_and_warn(const HibernateInfo *info);
