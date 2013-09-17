/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include <libudev.h>

#include "util.h"
#include "mkdir.h"
#include "fileio.h"

int main(int argc, char *argv[]) {
        struct udev *udev = NULL;
        struct udev_device *device = NULL;
        _cleanup_free_ char *saved = NULL;
        int r;

        if (argc != 3) {
                log_error("This program requires two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = mkdir_p("/var/lib/systemd/backlight", 0755);
        if (r < 0) {
                log_error("Failed to create backlight directory: %s", strerror(-r));
                goto finish;
        }

        udev = udev_new();
        if (!udev) {
                r = log_oom();
                goto finish;
        }

        errno = 0;
        device = udev_device_new_from_subsystem_sysname(udev, "backlight", argv[2]);
        if (!device) {
                if (errno != 0) {
                        log_error("Failed to get backlight device: %m");
                        r = -errno;
                } else
                        r = log_oom();

                goto finish;
        }

        if (!streq_ptr(udev_device_get_subsystem(device), "backlight")) {
                log_error("Not a backlight device: %s", argv[2]);
                r = -ENODEV;
                goto finish;
        }

        saved = strappend("/var/lib/systemd/backlight/", udev_device_get_sysname(device));
        if (!saved) {
                r = log_oom();
                goto finish;
        }

        if (streq(argv[1], "load")) {
                _cleanup_free_ char *value = NULL;

                r = read_one_line_file(saved, &value);
                if (r < 0) {

                        if (r == -ENOENT) {
                                r = 0;
                                goto finish;
                        }

                        log_error("Failed to read %s: %s", saved, strerror(-r));
                        goto finish;
                }

                r = udev_device_set_sysattr_value(device, "brightness", value);
                if (r < 0) {
                        log_error("Failed to write system attribute: %s", strerror(-r));
                        goto finish;
                }

        } else if (streq(argv[1], "save")) {
                const char *value;

                value = udev_device_get_sysattr_value(device, "brightness");
                if (!value) {
                        log_error("Failed to read system attribute: %s", strerror(-r));
                        goto finish;
                }

                r = write_string_file(saved, value);
                if (r < 0) {
                        log_error("Failed to write %s: %s", saved, strerror(-r));
                        goto finish;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                r = -EINVAL;
                goto finish;
        }

finish:
        if (device)
                udev_device_unref(device);

        if (udev)
                udev_unref(udev);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

}
