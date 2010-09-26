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

#include <errno.h>
#include <libudev.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/inotify.h>

#include "log.h"
#include "readahead-common.h"
#include "util.h"

int file_verify(int fd, const char *fn, off_t file_size_max, struct stat *st) {
        assert(fd >= 0);
        assert(fn);
        assert(st);

        if (fstat(fd, st) < 0) {
                log_warning("fstat(%s) failed: %m", fn);
                return -errno;
        }

        if (!S_ISREG(st->st_mode)) {
                log_debug("Not preloading special file %s", fn);
                return 0;
        }

        if (st->st_size <= 0 || st->st_size > file_size_max) {
                log_debug("Not preloading file %s with size out of bounds %zi", fn, st->st_size);
                return 0;
        }

        return 1;
}

int fs_on_ssd(const char *p) {
        struct stat st;
        struct udev *udev = NULL;
        struct udev_device *udev_device = NULL, *look_at = NULL;
        bool b = false;
        const char *devtype, *rotational, *model, *id;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (!(udev = udev_new()))
                return -ENOMEM;

        if (!(udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev)))
                goto finish;

        if ((devtype = udev_device_get_property_value(udev_device, "DEVTYPE")) &&
            streq(devtype, "partition"))
                look_at = udev_device_get_parent(udev_device);
        else
                look_at = udev_device;

        if (!look_at)
                goto finish;

        /* First, try high-level property */
        if ((id = udev_device_get_property_value(look_at, "ID_SSD"))) {
                b = streq(id, "1");
                goto finish;
        }

        /* Second, try kernel attribute */
        if ((rotational = udev_device_get_sysattr_value(look_at, "queue/rotational")))
                if ((b = streq(rotational, "0")))
                        goto finish;

        /* Finally, fallback to heuristics */
        if (!(look_at = udev_device_get_parent(look_at)))
                goto finish;

        if ((model = udev_device_get_sysattr_value(look_at, "model")))
                b = !!strstr(model, "SSD");

finish:
        if (udev_device)
                udev_device_unref(udev_device);

        if (udev)
                udev_unref(udev);

        return b;
}

bool enough_ram(void) {
        struct sysinfo si;

        assert_se(sysinfo(&si) >= 0);

        return si.totalram > 127 * 1024*1024; /* Enable readahead only
                                               * with at least 128MB
                                               * memory */
}

int open_inotify(void) {
        int fd;

        if ((fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK)) < 0) {
                log_error("Failed to create inotify handle: %m");
                return -errno;
        }

        mkdir("/dev/.systemd", 0755);
        mkdir("/dev/.systemd/readahead", 0755);

        if (inotify_add_watch(fd, "/dev/.systemd/readahead", IN_CREATE) < 0) {
                log_error("Failed to watch /dev/.systemd/readahead: %m");
                close_nointr_nofail(fd);
                return -errno;
        }

        return fd;
}
