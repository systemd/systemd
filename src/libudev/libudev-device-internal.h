/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "libudev.h"
#include "sd-device.h"

#include "libudev-private.h"
#include "macro.h"

/**
 * udev_device:
 *
 * Opaque object representing one kernel sys device.
 */
struct udev_device {
        /* real device object */
        sd_device *device;

        /* legacy */
        unsigned n_ref;

        struct udev_device *parent;
        bool parent_set;

        struct udev_list properties;
        uint64_t properties_generation;
        struct udev_list tags;
        uint64_t tags_generation;
        struct udev_list devlinks;
        uint64_t devlinks_generation;
        bool properties_read:1;
        bool tags_read:1;
        bool devlinks_read:1;
        struct udev_list sysattrs;
        bool sysattrs_read;
};

int udev_device_new(struct udev_device **ret);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct udev_device*, udev_device_unref);
