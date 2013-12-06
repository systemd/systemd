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

#include "util.h"
#include "mkdir.h"
#include "fileio.h"
#include "libudev.h"
#include "udev-util.h"

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_device_unref_ struct udev_device *device = NULL;
        _cleanup_free_ char *saved = NULL, *escaped_name = NULL, *escaped_path_id = NULL;
        const char *name, *path_id;
        int r;

        if (argc != 3) {
                log_error("This program requires two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = mkdir_p("/var/lib/systemd/rfkill", 0755);
        if (r < 0) {
                log_error("Failed to create rfkill directory: %s", strerror(-r));
                return EXIT_FAILURE;
        }

        udev = udev_new();
        if (!udev) {
                log_oom();
                return EXIT_FAILURE;
        }

        errno = 0;
        device = udev_device_new_from_subsystem_sysname(udev, "rfkill", argv[2]);
        if (!device) {
                if (errno != 0)
                        log_error("Failed to get rfkill device '%s': %m", argv[2]);
                else
                        log_oom();

                return EXIT_FAILURE;
        }

        name = udev_device_get_sysattr_value(device, "name");
        if (!name) {
                log_error("rfkill device has no name?");
                return EXIT_FAILURE;
        }

        escaped_name = cescape(name);
        if (!escaped_name) {
                log_oom();
                return EXIT_FAILURE;
        }

        path_id = udev_device_get_property_value(device, "ID_PATH");
        if (path_id) {
                escaped_path_id = cescape(path_id);
                if (!escaped_path_id) {
                        log_oom();
                        return EXIT_FAILURE;
                }

                saved = strjoin("/var/lib/systemd/rfkill/", escaped_path_id, ":", escaped_name, NULL);
        } else
                saved = strjoin("/var/lib/systemd/rfkill/", escaped_name, NULL);

        if (!saved) {
                log_oom();
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "load")) {
                _cleanup_free_ char *value = NULL;

                if (!shall_restore_state())
                        return EXIT_SUCCESS;

                r = read_one_line_file(saved, &value);
                if (r < 0) {

                        if (r == -ENOENT)
                                return EXIT_SUCCESS;

                        log_error("Failed to read %s: %s", saved, strerror(-r));
                        return EXIT_FAILURE;
                }

                r = udev_device_set_sysattr_value(device, "soft", value);
                if (r < 0) {
                        log_error("Failed to write system attribute: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

        } else if (streq(argv[1], "save")) {
                const char *value;

                value = udev_device_get_sysattr_value(device, "soft");
                if (!value) {
                        log_error("Failed to read system attribute: %s", strerror(-r));
                        return EXIT_FAILURE;
                }

                r = write_string_file(saved, value);
                if (r < 0) {
                        log_error("Failed to write %s: %s", saved, strerror(-r));
                        return EXIT_FAILURE;
                }

        } else {
                log_error("Unknown verb %s.", argv[1]);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
