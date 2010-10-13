/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

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
#include <fcntl.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <unistd.h>
#include <linux/loop.h>
#include <libudev.h>

#include "list.h"
#include "mount-setup.h"
#include "umount.h"
#include "util.h"

typedef struct MountPoint {
        char *path;
        LIST_FIELDS (struct MountPoint, mount_point);
} MountPoint;

/* Takes over possession of path */
static MountPoint *mount_point_alloc(char *path) {
        MountPoint *mp;

        if (!(mp = new(MountPoint, 1)))
                return NULL;

        mp->path = path;
        return mp;
}

static void mount_point_remove_and_free(MountPoint *mount_point, MountPoint **mount_point_list_head) {
        LIST_REMOVE(MountPoint, mount_point, *mount_point_list_head, mount_point);

        free(mount_point->path);
        free(mount_point);
}

static void mount_points_list_free(MountPoint **mount_point_list_head) {
        while (*mount_point_list_head)
                mount_point_remove_and_free(*mount_point_list_head, mount_point_list_head);
}

static int mount_points_list_get(MountPoint **mount_point_list_head) {
        FILE *proc_self_mountinfo;
        char *path, *p;
        unsigned int i;
        int r;

        if (!(proc_self_mountinfo = fopen("/proc/self/mountinfo", "re")))
                return -errno;

        for (i = 1;; i++) {
                int k;
                MountPoint *mp;

                path = p = NULL;

                if ((k = fscanf(proc_self_mountinfo,
                                "%*s "       /* (1) mount id */
                                "%*s "       /* (2) parent id */
                                "%*s "       /* (3) major:minor */
                                "%*s "       /* (4) root */
                                "%ms "       /* (5) mount point */
                                "%*s"        /* (6) mount options */
                                "%*[^-]"     /* (7) optional fields */
                                "- "         /* (8) separator */
                                "%*s "       /* (9) file system type */
                                "%*s"        /* (10) mount source */
                                "%*s"        /* (11) mount options 2 */
                                "%*[^\n]",   /* some rubbish at the end */
                                &path)) != 1) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/self/mountinfo:%u.", i);

                        free(path);
                        continue;
                }

                p = cunescape(path);
                free(path);

                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (mount_point_is_api(p)) {
                        free(p);
                        continue;
                }

                if (!(mp = mount_point_alloc(p))) {
                        free(p);
                        r = -ENOMEM;
                        goto finish;
                }

                LIST_PREPEND(MountPoint, mount_point, *mount_point_list_head, mp);
        }

        r = 0;

finish:
        fclose(proc_self_mountinfo);

        return r;
}

static int swap_list_get(MountPoint **swap_list_head) {
        FILE *proc_swaps;
        unsigned int i;
        int r;

        if (!(proc_swaps = fopen("/proc/swaps", "re")))
                return -errno;

        (void) fscanf(proc_swaps, "%*s %*s %*s %*s %*s\n");

        for (i = 2;; i++) {
                MountPoint *swap;
                char *dev = NULL, *d;
                int k;

                if ((k = fscanf(proc_swaps,
                                "%ms " /* device/file */
                                "%*s " /* type of swap */
                                "%*s " /* swap size */
                                "%*s " /* used */
                                "%*s\n", /* priority */
                                &dev)) != 1) {

                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/swaps:%u.", i);

                        free(dev);
                        continue;
                }

                if (endswith(dev, "(deleted)")) {
                        free(dev);
                        continue;
                }

                d = cunescape(dev);
                free(dev);

                if (!d) {
                        r = -ENOMEM;
                        goto finish;
                }

                swap = mount_point_alloc(d);
                if (!swap) {
                        free(d);
                        r = -ENOMEM;
                        goto finish;
                }

                LIST_PREPEND(MountPoint, mount_point, *swap_list_head, swap);
        }

        r = 0;

finish:
        fclose(proc_swaps);

        return r;
}

static int loopback_list_get(MountPoint **loopback_list_head) {
        int r;
        struct udev *udev;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        if (!(udev = udev_new())) {
                r = -ENOMEM;
                goto finish;
        }

        if (!(e = udev_enumerate_new(udev))) {
                r = -ENOMEM;
                goto finish;
        }

        if (udev_enumerate_add_match_subsystem(e, "block") < 0) {
                r = -EIO;
                goto finish;
        }

        if (udev_enumerate_add_match_sysname(e, "loop*") < 0) {
                r = -EIO;
                goto finish;
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto finish;
        }

        first = udev_enumerate_get_list_entry(e);

        udev_list_entry_foreach(item, first) {
                MountPoint *lb;
                struct udev_device *d;
                char *loop;
                const char *dn;

                if (!(d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item)))) {
                        r = -ENOMEM;
                        goto finish;
                }

                if ((dn = udev_device_get_devnode(d))) {
                        loop = strdup(dn);
                        udev_device_unref(d);

                        if (!loop) {
                                r = -ENOMEM;
                                goto finish;
                        }
                } else
                        udev_device_unref(d);

                if (!(lb = mount_point_alloc(loop))) {
                        free(loop);
                        r = -ENOMEM;
                        goto finish;
                }

                LIST_PREPEND(MountPoint, mount_point, *loopback_list_head, lb);
        }

        r = 0;

finish:
        if (e)
                udev_enumerate_unref(e);

        if (udev)
                udev_unref(udev);

        return r;
}

static int delete_loopback(const char *device) {
        int fd, r;

        if ((fd = open(device, O_RDONLY|O_CLOEXEC)) < 0)
                return -errno;

        r = ioctl(fd, LOOP_CLR_FD, 0);
        close_nointr_nofail(fd);

        /* ENXIO: not bound, so no error */
        return (r >= 0 || errno == ENXIO) ? 0 : -errno;
}

static int mount_points_list_umount(MountPoint **mount_point_list_head) {
        MountPoint *mp, *mp_next;
        int failed = 0;

        LIST_FOREACH_SAFE(mount_point, mp, mp_next, *mount_point_list_head) {
                if (streq(mp->path, "/"))
                        continue;

                /* Trying to umount. Forcing to umount if busy (only for NFS mounts) */
                if (umount2(mp->path, MNT_FORCE) == 0)
                        mount_point_remove_and_free(mp, mount_point_list_head);
                else {
                        log_debug("Could not unmount %s: %m", mp->path);
                        failed++;
                }
        }

        return failed;
}

static int mount_points_list_remount_read_only(MountPoint **mount_point_list_head) {
        MountPoint *mp, *mp_next;
        int failed = 0;

        LIST_FOREACH_SAFE(mount_point, mp, mp_next, *mount_point_list_head) {
                /* Trying to remount read-only */
                if (mount(NULL, mp->path, NULL, MS_MGC_VAL|MS_REMOUNT|MS_RDONLY, NULL) == 0)
                        mount_point_remove_and_free(mp, mount_point_list_head);
                else {
                        log_debug("Could not remount as read-only %s: %m", mp->path);
                        failed++;
                }
        }

        return failed;
}

static int swap_points_list_off(MountPoint **swap_list_head) {
        MountPoint *swap, *swap_next;
        int failed = 0;

        LIST_FOREACH_SAFE(mount_point, swap, swap_next, *swap_list_head) {
                if (swapoff(swap->path) == 0)
                        mount_point_remove_and_free(swap, swap_list_head);
                else {
                        log_debug("Could not swapoff %s: %m", swap->path);
                        failed++;
                }
        }

        return failed;
}

static int loopback_points_list_detach(MountPoint **loopback_list_head) {
        MountPoint *loopback, *loopback_next;
        int failed = 0;

        LIST_FOREACH_SAFE(mount_point, loopback, loopback_next, *loopback_list_head) {
                if (delete_loopback(loopback->path) == 0)
                        mount_point_remove_and_free(loopback, loopback_list_head);
                else {
                        log_debug("Could not delete loopback %s: %m", loopback->path);
                        failed++;
                }
        }

        return failed;
}

int umount_all(void) {
        int r;
        LIST_HEAD(MountPoint, mp_list_head);

        LIST_HEAD_INIT(MountPoint, mp_list_head);

        r = mount_points_list_get(&mp_list_head);
        if (r < 0)
                goto end;

        r = mount_points_list_umount(&mp_list_head);
        if (r <= 0)
                goto end;

        r = mount_points_list_remount_read_only(&mp_list_head);

  end:
        mount_points_list_free(&mp_list_head);

        return r;
}

int swapoff_all(void) {
        int r;
        LIST_HEAD(MountPoint, swap_list_head);

        LIST_HEAD_INIT(MountPoint, swap_list_head);

        r = swap_list_get(&swap_list_head);
        if (r < 0)
                goto end;

        r = swap_points_list_off(&swap_list_head);

  end:
        mount_points_list_free(&swap_list_head);

        return r;
}

int loopback_detach_all(void) {
        int r;
        LIST_HEAD(MountPoint, loopback_list_head);

        LIST_HEAD_INIT(MountPoint, loopback_list_head);

        r = loopback_list_get(&loopback_list_head);
        if (r < 0)
                goto end;

        r = loopback_points_list_detach(&loopback_list_head);

  end:
        mount_points_list_free(&loopback_list_head);

        return r;
}
