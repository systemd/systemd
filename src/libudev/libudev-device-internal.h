/***
  This file is part of systemd.

  Copyright 2008-2012 Kay Sievers <kay@vrfy.org>
  Copyright 2015 Tom Gundersen <teg@jklm.no>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#pragma once

#include "libudev.h"
#include "libudev-private.h"
#include "sd-device.h"

/**
 * udev_device:
 *
 * Opaque object representing one kernel sys device.
 */
struct udev_device {
        struct udev *udev;

        /* real device object */
        sd_device *device;

        /* legacy */
        int refcount;

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

struct udev_device *udev_device_new(struct udev *udev);
