/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>
#include <unistd.h>

#include <libudev.h>

#include "util.h"
#include "mkdir.h"

int main(int argc, char *argv[]) {

        struct udev *udev = NULL;
        struct udev_enumerate *enumerator = NULL;
        struct udev_list_entry *first, *item;
        int i;
        const char *seat = NULL;
        char **new_argv;
        char *path = NULL, *device_node = NULL;
        int r;
        FILE *f = NULL;

        /* This binary will go away as soon as X natively supports
         * display enumeration with udev in a way that covers both PCI
         * and USB. */

        /* This will simply determine the fb device id of the graphics
         * device assigned to a seat and write a configuration file
         * from it and then spawn the real X server. */

        /* If this file is removed, don't forget to remove the code
         * that invokes this in gdm and other display managers. */

        for (i = 1; i < argc; i++)
                if (streq(argv[i], "-seat"))
                        seat = argv[i+1];

        if (isempty(seat) || streq(seat, "seat0")) {
                argv[0] = (char*) X_SERVER;
                execv(X_SERVER, argv);
                log_error("Failed to execute real X server: %m");
                goto fail;
        }

        udev = udev_new();
        if (!udev) {
                log_error("Failed to allocate udev environment.");
                goto fail;
        }

        enumerator = udev_enumerate_new(udev);
        if (!enumerator) {
                log_error("Failed to allocate udev enumerator.");
                goto fail;
        }

        udev_enumerate_add_match_subsystem(enumerator, "graphics");
        udev_enumerate_add_match_tag(enumerator, seat);

        r = udev_enumerate_scan_devices(enumerator);
        if (r < 0) {
                log_error("Failed to enumerate devices.");
                goto fail;
        }

        first = udev_enumerate_get_list_entry(enumerator);
        udev_list_entry_foreach(item, first) {
                struct udev_device *d;
                const char *dn;

                d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!d)
                        continue;

                dn = udev_device_get_devnode(d);

                if (dn) {
                        device_node = strdup(dn);
                        if (!device_node) {
                                udev_device_unref(d);
                                log_error("Out of memory.");
                                goto fail;
                        }
                }

                udev_device_unref(d);

                if (device_node)
                        break;
        }

        if (!device_node) {
                log_error("Failed to find device node for seat %s.", seat);
                goto fail;
        }

        r = mkdir_safe_label("/run/systemd/multi-session-x", 0755, 0, 0);
        if (r < 0) {
                log_error("Failed to create directory: %s", strerror(-r));
                goto fail;
        }

        path = strappend("/run/systemd/multi-session-x/", seat);
        if (!path) {
                log_error("Out of memory.");
                goto fail;
        }

        f = fopen(path, "we");
        if (!f) {
                log_error("Failed to write configuration file: %m");
                goto fail;
        }

        fprintf(f,
                "Section \"Device\"\n"
                "        Identifier \"udev\"\n"
                "        Driver \"fbdev\"\n"
                "        Option \"fbdev\" \"%s\"\n"
                "EndSection\n"
                "Section \"ServerFlags\"\n"
                "        Option \"AutoAddDevices\" \"True\"\n"
                "        Option \"AllowEmptyInput\" \"True\"\n"
                "        Option \"DontVTSwitch\" \"True\"\n"
                "EndSection\n"
                "Section \"InputClass\"\n"
                "        Identifier \"Force Input Devices to Seat\"\n"
                "        Option \"GrabDevice\" \"True\"\n"
                "EndSection\n",
                device_node);

        fflush(f);

        if (ferror(f)) {
                log_error("Failed to write configuration file: %m");
                goto fail;
        }

        fclose(f);
        f = NULL;

        new_argv = alloca(sizeof(char*) * (argc + 3 + 1));
        memcpy(new_argv, argv, sizeof(char*) * (argc + 2 + 1));

        new_argv[0] = (char*) X_SERVER;
        new_argv[argc+0] = (char*) "-config";
        new_argv[argc+1] = path;
        new_argv[argc+2] = (char*) "-sharevts";
        new_argv[argc+3] = NULL;

        udev_enumerate_unref(enumerator);
        enumerator = NULL;

        udev_unref(udev);
        udev = NULL;

        free(device_node);
        device_node = NULL;

        execv(X_SERVER, new_argv);
        log_error("Failed to execute real X server: %m");

fail:
        if (enumerator)
                udev_enumerate_unref(enumerator);

        if (udev)
                udev_unref(udev);

        free(path);
        free(device_node);

        if (f)
                fclose(f);

        return EXIT_FAILURE;
}
