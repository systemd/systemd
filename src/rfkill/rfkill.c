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
        _cleanup_free_ char *saved = NULL, *ss = NULL, *escaped_name = NULL;
        const char *sysname, *name;
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

        sysname = strchr(argv[2], ':');
        if (!sysname) {
                log_error("Requires pair of subsystem and sysname for specifying rfkill device.");
                return EXIT_FAILURE;
        }

        ss = strndup(argv[2], sysname - argv[2]);
        if (!ss) {
                log_oom();
                return EXIT_FAILURE;
        }

        sysname++;

        if (!streq(ss, "rfkill")) {
                log_error("Not a rfkill device: '%s:%s'", ss, sysname);
                return EXIT_FAILURE;
        }

        errno = 0;
        device = udev_device_new_from_subsystem_sysname(udev, ss, sysname);
        if (!device) {
                if (errno != 0)
                        log_error("Failed to get rfkill device '%s:%s': %m", ss, sysname);
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

        saved = strjoin("/var/lib/systemd/rfkill/", escaped_name, NULL);
        if (!saved) {
                log_oom();
                return EXIT_FAILURE;
        }

        if (streq(argv[1], "load")) {
                _cleanup_free_ char *value = NULL;

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
