/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <linux/loop.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "detach-loopback.h"
#include "device-util.h"
#include "fd-util.h"
#include "shutdown.h"

typedef struct LoopbackDevice {
        char *path;
        dev_t devnum;
        LIST_FIELDS(struct LoopbackDevice, loopback_device);
} LoopbackDevice;

static void loopback_device_free(LoopbackDevice **head, LoopbackDevice *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(loopback_device, *head, m);

        free(m->path);
        free(m);
}

static void loopback_device_list_free(LoopbackDevice **head) {
        assert(head);

        while (*head)
                loopback_device_free(head, *head);
}

static int loopback_list_get(LoopbackDevice **head) {
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

        r = sd_device_enumerator_add_match_sysname(e, "loop*");
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "loop/backing_file", NULL, true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn;
                LoopbackDevice *lb;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                lb = new(LoopbackDevice, 1);
                if (!lb)
                        return -ENOMEM;

                *lb = (LoopbackDevice) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(loopback_device, *head, lb);
        }

        return 0;
}

static int delete_loopback(const char *device) {
        _cleanup_close_ int fd = -EBADF;
        struct loop_info64 info;

        assert(device);

        fd = open(device, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                log_debug_errno(errno, "Failed to open loopback device %s: %m", device);
                return errno == ENOENT ? 0 : -errno;
        }

        /* Loopback block devices don't sync in-flight blocks when we clear the fd, hence sync explicitly
         * first */
        (void) sync_with_progress(fd);

        if (ioctl(fd, LOOP_CLR_FD, 0) < 0) {
                if (errno == ENXIO) /* Nothing bound, didn't do anything */
                        return 0;

                if (errno != EBUSY)
                        return log_debug_errno(errno, "Failed to clear loopback device %s: %m", device);

                if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                        if (errno == ENXIO) /* What? Suddenly detached after all? That's fine by us then. */
                                return 1;

                        log_debug_errno(errno, "Failed to invoke LOOP_GET_STATUS64 on loopback device %s, ignoring: %m", device);
                        return -EBUSY; /* propagate original error */
                }

#if HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

                if (FLAGS_SET(info.lo_flags, LO_FLAGS_AUTOCLEAR)) /* someone else already set LO_FLAGS_AUTOCLEAR for us? fine by us */
                        return -EBUSY; /* propagate original error */

                info.lo_flags |= LO_FLAGS_AUTOCLEAR;
                if (ioctl(fd, LOOP_SET_STATUS64, &info) < 0) {
                        if (errno == ENXIO) /* Suddenly detached after all? Fine by us */
                                return 1;

                        log_debug_errno(errno, "Failed to set LO_FLAGS_AUTOCLEAR flag for loop device %s, ignoring: %m", device);
                } else
                        log_debug("Successfully set LO_FLAGS_AUTOCLEAR flag for loop device %s.", device);

                return -EBUSY;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                /* If the LOOP_CLR_FD above succeeded we'll see ENXIO here. */
                if (errno == ENXIO)
                        log_debug("Successfully detached loopback device %s.", device);
                else
                        log_debug_errno(errno, "Failed to invoke LOOP_GET_STATUS64 on loopback device %s, ignoring: %m", device); /* the LOOP_CLR_FD at least worked, let's hope for the best */

                return 1;
        }

#if HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

        /* Linux makes LOOP_CLR_FD succeed whenever LO_FLAGS_AUTOCLEAR is set without actually doing
         * anything. Very confusing. Let's hence not claim we did anything in this case. */
        if (FLAGS_SET(info.lo_flags, LO_FLAGS_AUTOCLEAR))
                log_debug("Successfully called LOOP_CLR_FD on a loopback device %s with autoclear set, which is a NOP.", device);
        else
                log_debug("Weird, LOOP_CLR_FD succeeded but the device is still attached on %s.", device);

        return -EBUSY; /* Nothing changed, the device is still attached, hence it apparently is still busy */
}

static int loopback_points_list_detach(LoopbackDevice **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0, usrdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device_harder("/", &rootdev);
        (void) block_get_whole_disk(rootdev, &rootdev);

        (void) get_block_device_harder("/usr", &usrdev);
        (void) block_get_whole_disk(usrdev, &usrdev);

        LIST_FOREACH(loopback_device, m, *head) {
                if ((major(rootdev) != 0 && rootdev == m->devnum) ||
                    (major(usrdev) != 0 && usrdev == m->devnum)) {
                        log_debug("Not detaching loopback device %s that backs the OS itself, skipping.", m->path);
                        n_failed++;
                        continue;
                }

                log_info("Detaching loopback %s.", m->path);
                r = delete_loopback(m->path);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not detach loopback %s: %m", m->path);
                        n_failed++;
                        continue;
                }
                if (r > 0)
                        *changed = true;

                loopback_device_free(head, m);
        }

        return n_failed;
}

int loopback_detach_all(bool *changed, bool last_try) {
        _cleanup_(loopback_device_list_free) LIST_HEAD(LoopbackDevice, loopback_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(loopback_list_head);

        r = loopback_list_get(&loopback_list_head);
        if (r < 0)
                return r;

        return loopback_points_list_detach(&loopback_list_head, changed, last_try);
}
