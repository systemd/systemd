/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"
#include "readahead-common.h"
#include "util.h"
#include "missing.h"
#include "fileio.h"
#include "libudev.h"
#include "udev-util.h"

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
                assert_cc(sizeof(st->st_size) == 8);
                log_debug("Not preloading file %s with size out of bounds %"PRIu64,
                          fn, st->st_size);
                return 0;
        }

        return 1;
}

int fs_on_ssd(const char *p) {
        struct stat st;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_device_unref_ struct udev_device *udev_device = NULL;
        struct udev_device *look_at = NULL;
        const char *devtype, *rotational, *model, *id;
        int r;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0) {
                _cleanup_fclose_ FILE *f = NULL;
                int mount_id;
                union file_handle_union h = { .handle.handle_bytes = MAX_HANDLE_SZ, };

                /* Might be btrfs, which exposes "ssd" as mount flag if it is on ssd.
                 *
                 * We first determine the mount ID here, if we can,
                 * and then lookup the mount ID in mountinfo to find
                 * the mount options. */

                r = name_to_handle_at(AT_FDCWD, p, &h.handle, &mount_id, AT_SYMLINK_FOLLOW);
                if (r < 0)
                        return false;

                f = fopen("/proc/self/mountinfo", "re");
                if (!f)
                        return false;

                for (;;) {
                        char line[LINE_MAX], *e;
                        _cleanup_free_ char *opts = NULL;
                        int mid;

                        if (!fgets(line, sizeof(line), f))
                                return false;

                        truncate_nl(line);

                        if (sscanf(line, "%i", &mid) != 1)
                                continue;

                        if (mid != mount_id)
                                continue;

                        e = strstr(line, " - ");
                        if (!e)
                                continue;

                        if (sscanf(e+3, "%*s %*s %ms", &opts) != 1)
                                continue;

                        if (streq(opts, "ssd") || startswith(opts, "ssd,") || endswith(opts, ",ssd") || strstr(opts, ",ssd,"))
                                return true;
                }

                return false;
        }

        udev = udev_new();
        if (!udev)
                return -ENOMEM;

        udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev);
        if (!udev_device)
                return false;

        devtype = udev_device_get_property_value(udev_device, "DEVTYPE");
        if (devtype && streq(devtype, "partition"))
                look_at = udev_device_get_parent(udev_device);
        else
                look_at = udev_device;

        if (!look_at)
                return false;

        /* First, try high-level property */
        id = udev_device_get_property_value(look_at, "ID_SSD");
        if (id)
                return streq(id, "1");

        /* Second, try kernel attribute */
        rotational = udev_device_get_sysattr_value(look_at, "queue/rotational");
        if (rotational)
                return streq(rotational, "0");

        /* Finally, fallback to heuristics */
        look_at = udev_device_get_parent(look_at);
        if (!look_at)
                return false;

        model = udev_device_get_sysattr_value(look_at, "model");
        if (model)
                return !!strstr(model, "SSD");

        return false;
}

int fs_on_read_only(const char *p) {
        struct stat st;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_device_unref_ struct udev_device *udev_device = NULL;
        const char *read_only;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return false;

        udev = udev_new();
        if (!udev)
                return -ENOMEM;

        udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev);
        if (!udev_device)
                return false;

        read_only = udev_device_get_sysattr_value(udev_device, "ro");
        if (read_only)
                return streq(read_only, "1");

        return false;
}

bool enough_ram(void) {
        struct sysinfo si;

        assert_se(sysinfo(&si) >= 0);

        /* Enable readahead only with at least 128MB memory */
        return si.totalram > 127 * 1024*1024 / si.mem_unit;
}

static void mkdirs(void) {
        if (mkdir("/run/systemd", 0755) && errno != EEXIST)
                log_warning("Failed to create /run/systemd: %m");
        if (mkdir("/run/systemd/readahead", 0755) && errno != EEXIST)
                log_warning("Failed to create /run/systemd: %m");
}

int open_inotify(void) {
        int fd;

        fd = inotify_init1(IN_CLOEXEC|IN_NONBLOCK);
        if (fd < 0) {
                log_error("Failed to create inotify handle: %m");
                return -errno;
        }

        mkdirs();

        if (inotify_add_watch(fd, "/run/systemd/readahead", IN_CREATE) < 0) {
                log_error("Failed to watch /run/systemd/readahead: %m");
                safe_close(fd);
                return -errno;
        }

        return fd;
}

ReadaheadShared *shared_get(void) {
        _cleanup_close_ int fd = -1;
        ReadaheadShared *m = NULL;

        mkdirs();

        fd = open("/run/systemd/readahead/shared", O_CREAT|O_RDWR|O_CLOEXEC, 0644);
        if (fd < 0) {
                log_error("Failed to create shared memory segment: %m");
                return NULL;
        }

        if (ftruncate(fd, sizeof(ReadaheadShared)) < 0) {
                log_error("Failed to truncate shared memory segment: %m");
                return NULL;
        }

        m = mmap(NULL, sizeof(ReadaheadShared), PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) {
                log_error("Failed to mmap shared memory segment: %m");
                return NULL;
        }

        return m;
}

/* We use 20K instead of the more human digestable 16K here. Why?
   Simply so that it is more unlikely that users end up picking this
   value too so that we can recognize better whether the user changed
   the value while we had it temporarily bumped. */
#define BUMP_REQUEST_NR (20*1024u)

int block_bump_request_nr(const char *p) {
        struct stat st;
        uint64_t u;
        char *ap = NULL, *line = NULL;
        int r;
        dev_t d;

        assert(p);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return 0;

        d = st.st_dev;
        block_get_whole_disk(d, &d);

        if (asprintf(&ap, "/sys/dev/block/%u:%u/queue/nr_requests", major(d), minor(d)) < 0) {
                r= -ENOMEM;
                goto finish;
        }

        r = read_one_line_file(ap, &line);
        if (r < 0) {
                if (r == -ENOENT)
                        r = 0;
                goto finish;
        }

        r = safe_atou64(line, &u);
        if (r >= 0 && u >= BUMP_REQUEST_NR) {
                r = 0;
                goto finish;
        }

        free(line);
        line = NULL;

        if (asprintf(&line, "%u", BUMP_REQUEST_NR) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = write_string_file(ap, line);
        if (r < 0)
                goto finish;

        log_info("Bumped block_nr parameter of %u:%u to %u. This is a temporary hack and should be removed one day.", major(d), minor(d), BUMP_REQUEST_NR);
        r = 1;

finish:
        free(ap);
        free(line);

        return r;
}

int block_get_readahead(const char *p, uint64_t *bytes) {
        struct stat st;
        char *ap = NULL, *line = NULL;
        int r;
        dev_t d;
        uint64_t u;

        assert(p);
        assert(bytes);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return 0;

        d = st.st_dev;
        block_get_whole_disk(d, &d);

        if (asprintf(&ap, "/sys/dev/block/%u:%u/bdi/read_ahead_kb", major(d), minor(d)) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = read_one_line_file(ap, &line);
        if (r < 0)
                goto finish;

        r = safe_atou64(line, &u);
        if (r < 0)
                goto finish;

        *bytes = u * 1024ULL;

finish:
        free(ap);
        free(line);

        return r;
}

int block_set_readahead(const char *p, uint64_t bytes) {
        struct stat st;
        char *ap = NULL, *line = NULL;
        int r;
        dev_t d;

        assert(p);
        assert(bytes);

        if (stat(p, &st) < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return 0;

        d = st.st_dev;
        block_get_whole_disk(d, &d);

        if (asprintf(&ap, "/sys/dev/block/%u:%u/bdi/read_ahead_kb", major(d), minor(d)) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        if (asprintf(&line, "%llu", bytes / 1024ULL) < 0) {
                r = -ENOMEM;
                goto finish;
        }

        r = write_string_file(ap, line);
        if (r < 0)
                goto finish;

finish:
        free(ap);
        free(line);

        return r;
}
