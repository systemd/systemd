/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Michal Sekletar

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

#include <assert.h>
#include <blkid/blkid.h>
#include <errno.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <string-util.h>

#include "alloc-util.h"
#include "boot-util.h"
#include "blkid-util.h"

int esp_verify_fs_type(const char *p) {
        int r;
        struct statfs stfs;

        assert(p);

        r = statfs(p, &stfs);
        if (r < 0)
                return -errno;

        if (stfs.f_type != MSDOS_SUPER_MAGIC)
                return -ENODEV;

        return 0;
}

int esp_verify_path_is_esp_root(const char *p) {
        int r;
        struct stat st, st1;
        const char *esp_parent;

        assert(p);

        r = stat(p, &st);
        if (r < 0)
                return -errno;

        if (major(st.st_dev) == 0)
                return -EINVAL;

        esp_parent = strjoina(p, "/..");
        r = stat(esp_parent, &st1);
        if (r < 0)
                return -ENOTBLK;

        if (st.st_dev == st1.st_dev)
                return -ENODEV;

        return 0;
}

int esp_verify_partition(const char *p, uint32_t *part, uint64_t *pstart, uint64_t *psize, sd_id128_t *uuid) {
        int r;
        _cleanup_free_ char *t = NULL;
        const char *v;
        struct stat st;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;

        r = esp_verify_fs_type(p);
        if (r < 0)
                return r;

        r = stat(p, &st);
        if (r < 0)
                return -errno;

        r = asprintf(&t, "/dev/block/%u:%u", major(st.st_dev), minor(st.st_dev));
        if (r < 0)
                return -ENOMEM;

        b = blkid_new_probe_from_filename(t);
        if (!b) {
                if (errno == 0)
                        return -ENOMEM;
        }

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r != 0)
                return -EIO;

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return errno ? -errno : -EIO;

        if (!streq(v, "gpt"))
                return -ENODEV;

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0)
                return errno ? -errno : -EIO;

        if (!streq(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
                return -ENODEV;

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0)
                return errno ? -errno : -EIO;

        if (uuid) {
                r = sd_id128_from_string(v, uuid);
                if (r < 0)
                        return -EIO;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0)
                return errno ? -errno : -EIO;

        if (part)
                *part = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0)
                return  errno ? -errno : -EIO;

        if (pstart)
                *pstart = strtoul(v, NULL, 10);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0)
                return errno ? -errno : -EIO;

        if (psize)
                *psize = strtoul(v, NULL, 10);

        return 0;
}
