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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/input.h>

#include "udev.h"

static const struct key *keyboard_lookup_key(const char *str, unsigned int len);
#include "keyboard-keys-from-name.h"
#include "keyboard-keys-to-name.h"

static int install_force_release(struct udev_device *dev, const unsigned int *release, unsigned int release_count) {
        struct udev_device *atkbd;
        const char *cur;
        char codes[4096];
        char *s;
        size_t l;
        unsigned int i;
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
                l = strpcpyf(&s, l, ",%d", release[i]);

        log_debug("keyboard: updating force-release list with '%s'", codes);
        ret = udev_device_set_sysattr_value(atkbd, "force_release", codes);
        if (ret < 0)
                log_error("Error writing force-release attribute: %s", strerror(-ret));
        return ret;
}

static int builtin_keyboard(struct udev_device *dev, int argc, char *argv[], bool test) {
        struct udev_list_entry *entry;
        struct {
                unsigned int scan;
                unsigned int key;
        } map[1024];
        unsigned int map_count = 0;
        unsigned int release[1024];
        unsigned int release_count = 0;

        udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev)) {
                const char *key;
                unsigned int scancode;
                char *endptr;
                const char *keycode;
                const struct key *k;

                key = udev_list_entry_get_name(entry);
                if (!startswith(key, "KEYBOARD_KEY_"))
                        continue;

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

                /* translate identifier to key code */
                k = keyboard_lookup_key(keycode, strlen(keycode));
                if (!k) {
                        log_error("Error, unknown key identifier '%s'", keycode);
                        continue;
                }

                map[map_count].scan = scancode;
                map[map_count].key = k->id;
                if (map_count < ELEMENTSOF(map)-1)
                        map_count++;
        }

        if (map_count > 0 || release_count > 0) {
                const char *node;
                int fd;
                unsigned int i;

                node = udev_device_get_devnode(dev);
                if (!node) {
                        log_error("Error, no device node for '%s'", udev_device_get_syspath(dev));
                        return EXIT_FAILURE;
                }

                fd = open(udev_device_get_devnode(dev), O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                if (fd < 0) {
                        log_error("Error, opening device '%s': %m", node);
                        return EXIT_FAILURE;
                }

                /* install list of map codes */
                for (i = 0; i < map_count; i++) {
                        log_debug("keyboard: mapping scan code %d (0x%x) to key code %d (0x%x)",
                                  map[i].scan, map[i].scan, map[i].key, map[i].key);
                        if (ioctl(fd, EVIOCSKEYCODE, &map[i]) < 0)
                                log_error("Error calling EVIOCSKEYCODE on device node '%s' (scan code 0x%x, key code %d): %m", node, map[i].scan, map[i].key);
                }

                /* install list of force-release codes */
                if (release_count > 0)
                        install_force_release(dev, release, release_count);

                close(fd);
        }

        return EXIT_SUCCESS;
}

const struct udev_builtin udev_builtin_keyboard = {
        .name = "keyboard",
        .cmd = builtin_keyboard,
        .help = "keyboard scan code to key mapping",
};
