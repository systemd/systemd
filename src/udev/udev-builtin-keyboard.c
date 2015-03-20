/***
  This file is part of systemd.

  Copyright 2013 Kay Sievers <kay@vrfy.org>

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/input.h>

#include "udev.h"

static const struct key *keyboard_lookup_key(const char *str, unsigned len);
#include "keyboard-keys-from-name.h"

static int install_force_release(struct udev_device *dev, const unsigned *release, unsigned release_count) {
        struct udev_device *atkbd;
        const char *cur;
        char codes[4096];
        char *s;
        size_t l;
        unsigned i;
        int ret;

        atkbd = udev_device_get_parent_with_subsystem_devtype(dev, "serio", NULL);
        if (!atkbd)
                return -ENODEV;

        cur = udev_device_get_sysattr_value(atkbd, "force_release");
        if (!cur)
                return -ENODEV;

        s = codes;
        l = sizeof(codes);

        /* copy current content */
        l = strpcpy(&s, l, cur);

        /* append new codes */
        for (i = 0; i < release_count; i++)
                l = strpcpyf(&s, l, ",%u", release[i]);

        log_debug("keyboard: updating force-release list with '%s'", codes);
        ret = udev_device_set_sysattr_value(atkbd, "force_release", codes);
        if (ret < 0)
                log_error_errno(ret, "Error writing force-release attribute: %m");
        return ret;
}

static void map_keycode(int fd, const char *devnode, int scancode, const char *keycode)
{
        struct {
                unsigned scan;
                unsigned key;
        } map;
        char *endptr;
        const struct key *k;
        unsigned keycode_num;

        /* translate identifier to key code */
        k = keyboard_lookup_key(keycode, strlen(keycode));
        if (k) {
                keycode_num = k->id;
        } else {
                /* check if it's a numeric code already */
                keycode_num = strtoul(keycode, &endptr, 0);
                if (endptr[0] !='\0') {
                        log_error("Error, unknown key identifier '%s'", keycode);
                        return;
                }
        }

        map.scan = scancode;
        map.key = keycode_num;

        log_debug("keyboard: mapping scan code %d (0x%x) to key code %d (0x%x)",
                  map.scan, map.scan, map.key, map.key);

        if (ioctl(fd, EVIOCSKEYCODE, &map) < 0)
                log_error_errno(errno, "Error calling EVIOCSKEYCODE on device node '%s' (scan code 0x%x, key code %d): %m", devnode, map.scan, map.key);
}

static int builtin_keyboard(struct udev_device *dev, int argc, char *argv[], bool test) {
        struct udev_list_entry *entry;
        unsigned release[1024];
        unsigned release_count = 0;
        _cleanup_close_ int fd = -1;
        const char *node;

        node = udev_device_get_devnode(dev);
        if (!node) {
                log_error("Error, no device node for '%s'", udev_device_get_syspath(dev));
                return EXIT_FAILURE;
        }

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev)) {
                const char *key;
                char *endptr;

                key = udev_list_entry_get_name(entry);
                if (startswith(key, "KEYBOARD_KEY_")) {
                        const char *keycode;
                        unsigned scancode;

                        /* KEYBOARD_KEY_<hex scan code>=<key identifier string> */
                        scancode = strtoul(key + 13, &endptr, 16);
                        if (endptr[0] != '\0') {
                                log_error("Error, unable to parse scan code from '%s'", key);
                                continue;
                        }

                        keycode = udev_list_entry_get_value(entry);

                        /* a leading '!' needs a force-release entry */
                        if (keycode[0] == '!') {
                                keycode++;

                                release[release_count] = scancode;
                                if (release_count <  ELEMENTSOF(release)-1)
                                        release_count++;

                                if (keycode[0] == '\0')
                                        continue;
                        }

                        if (fd == -1) {
                                fd = open(node, O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                                if (fd < 0) {
                                        log_error_errno(errno, "Error, opening device '%s': %m", node);
                                        return EXIT_FAILURE;
                                }
                        }

                        map_keycode(fd, node, scancode, keycode);
                }
        }

        /* install list of force-release codes */
        if (release_count > 0)
                install_force_release(dev, release, release_count);

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_keyboard = {
        .name = "keyboard",
        .cmd = builtin_keyboard,
        .help = "Keyboard scan code to key mapping",
};
