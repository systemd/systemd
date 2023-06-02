/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <linux/major.h>
#include <linux/raid/md_u.h>
#include <sys/ioctl.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "detach-md.h"
#include "device-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "string-util.h"
#include "umount.h"

static int md_list_get(MountPoint **head) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        assert(head);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysname(e, "md*");
        if (r < 0)
                return r;

        /* Filter out partitions. */
        r = sd_device_enumerator_add_match_property(e, "DEVTYPE", "disk");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn, *md_level;
                MountPoint *m;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                r = sd_device_get_property_value(d, "MD_LEVEL", &md_level);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get MD_LEVEL property for %s, ignoring: %m", dn);
                        continue;
                }

                /* MD "containers" are a special type of MD devices, used for external metadata.  Since it
                 * doesn't provide RAID functionality in itself we don't need to stop it. */
                if (streq(md_level, "container"))
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                m = new(MountPoint, 1);
                if (!m)
                        return -ENOMEM;

                *m = (MountPoint) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(mount_point, *head, m);
        }

        return 0;
}

static int delete_md(MountPoint *m) {
        _cleanup_close_ int fd = -EBADF;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open(m->path, O_RDONLY|O_CLOEXEC|O_EXCL);
        if (fd < 0)
                return -errno;

        if (fsync(fd) < 0)
                log_debug_errno(errno, "Failed to sync MD block device %s, ignoring: %m", m->path);

        return RET_NERRNO(ioctl(fd, STOP_ARRAY, NULL));
}

static int md_points_list_detach(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);

        LIST_FOREACH(mount_point, m, *head) {
                if (major(rootdev) != 0 && rootdev == m->devnum) {
                        n_failed ++;
                        continue;
                }

                log_info("Stopping MD %s (" DEVNUM_FORMAT_STR ").", m->path, DEVNUM_FORMAT_VAL(m->devnum));
                r = delete_md(m);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not stop MD %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

int md_detach_all(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, md_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(md_list_head);

        r = md_list_get(&md_list_head);
        if (r < 0)
                return r;

        return md_points_list_detach(&md_list_head, changed, last_try);
}
