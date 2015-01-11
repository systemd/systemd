/*
 * evdev_id - extracts miscellaneous information from evdev devices
 *
 * Copyright (C) 2014 Red Hat
 * Author:
 *   Carlos Garnacho  <carlosg@gnome.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with keymap; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 */

#include <linux/input.h>
#include "udev.h"
#include "util.h"

static inline int abs_size_mm(const struct input_absinfo *absinfo) {
        /* Resolution is defined to be in units/mm for ABS_X/Y */
        return (absinfo->maximum - absinfo->minimum) / absinfo->resolution;
}

static void extract_info(struct udev_device *dev, const char *devpath, bool test) {
        char width[DECIMAL_STR_MAX(int)], height[DECIMAL_STR_MAX(int)];
        struct input_absinfo xabsinfo = {}, yabsinfo = {};
        _cleanup_close_ int fd = -1;

        fd = open(devpath, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return;

        if (ioctl(fd, EVIOCGABS(ABS_X), &xabsinfo) < 0 ||
            ioctl(fd, EVIOCGABS(ABS_Y), &yabsinfo) < 0)
                return;

        if (xabsinfo.resolution <= 0 || yabsinfo.resolution <= 0)
                return;

        snprintf(width, sizeof(width), "%d", abs_size_mm(&xabsinfo));
        snprintf(height, sizeof(height), "%d", abs_size_mm(&yabsinfo));

        udev_builtin_add_property(dev, test, "ID_INPUT_WIDTH_MM", width);
        udev_builtin_add_property(dev, test, "ID_INPUT_HEIGHT_MM", height);
}

static int builtin_evdev_id(struct udev_device *dev, int argc, char *argv[], bool test) {
        const char *subsystem;
        const char *devnode;

        subsystem = udev_device_get_subsystem(dev);

        if (!subsystem || !streq(subsystem, "input"))
                return EXIT_SUCCESS;

        devnode = udev_device_get_devnode(dev);
        /* not an evdev node */
        if (!devnode)
                return EXIT_SUCCESS;

        extract_info(dev, devnode, test);

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_evdev_id = {
        .name = "evdev_id",
        .cmd = builtin_evdev_id,
        .help = "evdev devices information",
};
