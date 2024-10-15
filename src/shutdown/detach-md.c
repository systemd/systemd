/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <linux/major.h>
#include <linux/raid/md_u.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "detach-md.h"
#include "device-util.h"
#include "devnum-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "shutdown.h"
#include "string-util.h"

typedef struct RaidDevice {
        char *path;
        dev_t devnum;
        LIST_FIELDS(struct RaidDevice, raid_device);
} RaidDevice;

static void raid_device_free(RaidDevice **head, RaidDevice *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(raid_device, *head, m);

        free(m->path);
        free(m);
}

static void raid_device_list_free(RaidDevice **head) {
        assert(head);

        while (*head)
                raid_device_free(head, *head);
}

static int md_list_get(RaidDevice **head) {
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
                RaidDevice *m;
                dev_t devnum;

                r = sd_device_get_devname(d, &dn);
                if (r < 0) {
                        log_device_warning_errno(d, r, "Failed to get name of enumerated device, ignoring: %m");
                        continue;
                }

                r = sd_device_get_devnum(d, &devnum);
                if (r < 0) {
                        log_device_warning_errno(d, r, "Failed to get devno of enumerated device '%s', ignoring device: %m", dn);
                        continue;
                }

                /* MD "containers" are a special type of MD devices, used for external metadata. Since they
                 * don't provide RAID functionality in themselves we don't need to stop them. Note that the
                 * MD_LEVEL udev property is set by mdadm in userspace, which is an optional package. Hence
                 * let's handle gracefully if the property is missing. */

                r = sd_device_get_property_value(d, "MD_LEVEL", &md_level);
                if (r < 0)
                        log_device_full_errno(d,
                                              r == -ENOENT ? LOG_DEBUG : LOG_WARNING,
                                              r,
                                              "Failed to get MD_LEVEL property for %s, assuming regular MD device, not a container: %m", dn);
                else if (streq(md_level, "container")) {
                        log_device_debug(d, "Skipping MD device '%s' because it is a container MD device.", dn);
                        continue;
                }

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                m = new(RaidDevice, 1);
                if (!m)
                        return -ENOMEM;

                *m = (RaidDevice) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(raid_device, *head, m);
        }

        return 0;
}

static int delete_md(RaidDevice *m) {
        _cleanup_close_ int fd = -EBADF;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open(m->path, O_RDONLY|O_CLOEXEC|O_EXCL);
        if (fd < 0)
                return -errno;

        (void) sync_with_progress(fd);

        return RET_NERRNO(ioctl(fd, STOP_ARRAY, NULL));
}

static int md_points_list_detach(RaidDevice **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0, usrdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);
        (void) get_block_device("/usr", &usrdev);

        LIST_FOREACH(raid_device, m, *head) {
                if ((major(rootdev) != 0 && rootdev == m->devnum) ||
                    (major(usrdev) != 0 && usrdev == m->devnum)) {
                        log_debug("Not detaching MD %s that backs the OS itself, skipping.", m->path);
                        n_failed++;
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
                raid_device_free(head, m);
        }

        return n_failed;
}

int md_detach_all(bool *changed, bool last_try) {
        _cleanup_(raid_device_list_free) LIST_HEAD(RaidDevice, md_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(md_list_head);

        r = md_list_get(&md_list_head);
        if (r < 0)
                return r;

        return md_points_list_detach(&md_list_head, changed, last_try);
}
