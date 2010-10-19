/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <libudev.h>

#include "util.h"
#include "ac-power.h"

int on_ac_power(void) {
        int r;

        struct udev *udev;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        bool found_offline = false, found_online = false;

        if (!(udev = udev_new())) {
                r = -ENOMEM;
                goto finish;
        }

        if (!(e = udev_enumerate_new(udev))) {
                r = -ENOMEM;
                goto finish;
        }

        if (udev_enumerate_add_match_subsystem(e, "power_supply") < 0) {
                r = -EIO;
                goto finish;
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto finish;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                const char *type, *online;

                if (!(d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item)))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(type = udev_device_get_sysattr_value(d, "type")))
                        goto next;

                if (!streq(type, "Mains"))
                        goto next;

                if (!(online = udev_device_get_sysattr_value(d, "online")))
                        goto next;

                if (streq(online, "1")) {
                        found_online = true;
                        break;
                } else if (streq(online, "0"))
                        found_offline = true;

        next:
                udev_device_unref(d);
        }

        r = found_online || !found_offline;

finish:
        if (e)
                udev_enumerate_unref(e);

        if (udev)
                udev_unref(udev);

        return r;
}
