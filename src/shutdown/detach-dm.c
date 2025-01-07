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
#include "shutdown.h"

typedef struct DeviceMapper {
        char *path;
        dev_t devnum;
        LIST_FIELDS(struct DeviceMapper, device_mapper);
} DeviceMapper;

static void device_mapper_free(DeviceMapper **head, DeviceMapper *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(device_mapper, *head, m);

        free(m->path);
        free(m);
}

static void device_mapper_list_free(DeviceMapper **head) {
        assert(head);

        while (*head)
                device_mapper_free(head, *head);
}

static int dm_list_get(DeviceMapper **head) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
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
                DeviceMapper *m;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                m = new(DeviceMapper, 1);
                if (!m)
                        return -ENOMEM;

                *m = (DeviceMapper) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(device_mapper, *head, m);
        }

        return 0;
}

static int delete_dm(DeviceMapper *m) {
        _cleanup_close_ int fd = -EBADF;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open(m->path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                log_debug_errno(errno, "Failed to open DM block device %s for syncing, ignoring: %m", m->path);
        else {
                (void) sync_with_progress(fd);
                fd = safe_close(fd);
        }

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open /dev/mapper/control: %m");

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

static int dm_points_list_detach(DeviceMapper **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0, usrdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);
        (void) get_block_device("/usr", &usrdev);

        LIST_FOREACH(device_mapper, m, *head) {
                if ((major(rootdev) != 0 && rootdev == m->devnum) ||
                    (major(usrdev) != 0 && usrdev == m->devnum)) {
                        log_debug("Not detaching DM %s that backs the OS itself, skipping.", m->path);
                        n_failed++;
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
                device_mapper_free(head, m);
        }

        return n_failed;
}

int dm_detach_all(bool *changed, bool last_try) {
        _cleanup_(device_mapper_list_free) LIST_HEAD(DeviceMapper, dm_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(dm_list_head);

        r = dm_list_get(&dm_list_head);
        if (r < 0)
                return r;

        return dm_points_list_detach(&dm_list_head, changed, last_try);
}
