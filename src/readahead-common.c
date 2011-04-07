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
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libudev.h>

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
                log_debug("Not preloading file %s with size out of bounds %llu", fn, (unsigned long long) st->st_size);
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

        if (major(st.st_dev) == 0)
                return false;

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

int fs_on_read_only(const char *p) {
        struct stat st;
        struct udev *udev = NULL;
        struct udev_device *udev_device = NULL;
        bool b = false;
        const char *read_only;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return false;

        if (!(udev = udev_new()))
                return -ENOMEM;

        if (!(udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev)))
                goto finish;

        if ((read_only = udev_device_get_sysattr_value(udev_device, "ro")))
                if ((b = streq(read_only, "1")))
                        goto finish;

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

        mkdir("/run/systemd", 0755);
        mkdir("/run/systemd/readahead", 0755);

        if (inotify_add_watch(fd, "/run/systemd/readahead", IN_CREATE) < 0) {
                log_error("Failed to watch /run/systemd/readahead: %m");
                close_nointr_nofail(fd);
                return -errno;
        }

        return fd;
}

ReadaheadShared *shared_get(void) {
        int fd;
        ReadaheadShared *m = NULL;

        mkdir("/run/systemd", 0755);
        mkdir("/run/systemd/readahead", 0755);

        if ((fd = open("/run/systemd/readahead/shared", O_CREAT|O_RDWR|O_CLOEXEC, 0644)) < 0) {
                log_error("Failed to create shared memory segment: %m");
                goto finish;
        }

        if (ftruncate(fd, sizeof(ReadaheadShared)) < 0) {
                log_error("Failed to truncate shared memory segment: %m");
                goto finish;
        }

        if ((m = mmap(NULL, sizeof(ReadaheadShared), PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
                log_error("Failed to mmap shared memory segment: %m");
                m = NULL;
                goto finish;
        }

finish:
        if (fd >= 0)
                close_nointr_nofail(fd);

        return m;
}

#define BUMP_REQUEST_NR (16*1024)

int bump_request_nr(const char *p) {
        struct stat st;
        struct udev *udev = NULL;
        struct udev_device *udev_device = NULL, *look_at = NULL;
        const char *nr_requests;
        uint64_t u;
        char nr[64], *ap = NULL;
        int r;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return 0;

        if (!(udev = udev_new()))
                return -ENOMEM;

        if (!(udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev))) {
                r = -ENOENT;
                goto finish;
        }

        look_at = udev_device;
        if (!(nr_requests = udev_device_get_sysattr_value(look_at, "queue/nr_requests"))) {

                /* Hmm, if the block device doesn't have a queue
                 * subdir, the let's look in the parent */
                look_at = udev_device_get_parent(udev_device);
                nr_requests = udev_device_get_sysattr_value(look_at, "queue/nr_requests");
        }

        if (!nr_requests) {
                r = -ENOENT;
                goto finish;
        }

        if (safe_atou64(nr_requests, &u) >= 0 && u >= BUMP_REQUEST_NR) {
                r = 0;
                goto finish;
        }

        if (asprintf(&ap, "%s/queue/nr_requests", udev_device_get_syspath(look_at)) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        snprintf(nr, sizeof(nr), "%lu", (unsigned long) BUMP_REQUEST_NR);

        if ((r = write_one_line_file(ap, nr)) < 0)
                goto finish;

        log_info("Bumped block_nr parameter of %s to %lu. This is a temporary hack and should be removed one day.", udev_device_get_devnode(look_at), (unsigned long) BUMP_REQUEST_NR);
        r = 1;

finish:
        if (udev_device)
                udev_device_unref(udev_device);

        if (udev)
                udev_unref(udev);

        free(ap);

        return r;
}
