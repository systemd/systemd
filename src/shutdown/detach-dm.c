/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "detach-dm.h"
#include "device-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "sync-util.h"
#include "umount.h"

static int dm_list_get(MountPoint **head) {
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

        r = sd_device_enumerator_add_match_sysname(e, "dm-*");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn;
                MountPoint *m;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
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

static int delete_dm(MountPoint *m) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = fsync_path_at(AT_FDCWD, m->path);
        if (r < 0)
                log_debug_errno(r, "Failed to sync DM block device %s, ignoring: %m", m->path);

        return RET_NERRNO(ioctl(fd, DM_DEV_REMOVE, &(struct dm_ioctl) {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = sizeof(struct dm_ioctl),
                .dev = m->devnum,
        }));
}

static int dm_points_list_detach(MountPoint **head, bool *changed, bool last_try) {
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

                log_info("Detaching DM %s (" DEVNUM_FORMAT_STR ").", m->path, DEVNUM_FORMAT_VAL(m->devnum));
                r = delete_dm(m);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not detach DM %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

int dm_detach_all(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, dm_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(dm_list_head);

        r = dm_list_get(&dm_list_head);
        if (r < 0)
                return r;

        return dm_points_list_detach(&dm_list_head, changed, last_try);
}
