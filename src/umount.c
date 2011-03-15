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
#include <linux/dm-ioctl.h>
#include <libudev.h>

#include "list.h"
#include "mount-setup.h"
#include "umount.h"
#include "util.h"

typedef struct MountPoint {
        char *path;
        dev_t devnum;
        bool skip_ro;
        LIST_FIELDS (struct MountPoint, mount_point);
} MountPoint;

static void mount_point_free(MountPoint **head, MountPoint *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(MountPoint, mount_point, *head, m);

        free(m->path);
        free(m);
}

static void mount_points_list_free(MountPoint **head) {
        assert(head);

        while (*head)
                mount_point_free(head, *head);
}

static int mount_points_list_get(MountPoint **head) {
        FILE *proc_self_mountinfo;
        char *path, *p;
        unsigned int i;
        int r;

        assert(head);

        if (!(proc_self_mountinfo = fopen("/proc/self/mountinfo", "re")))
                return -errno;

        for (i = 1;; i++) {
                int k;
                MountPoint *m;
                char *root;
                bool skip_ro;

                path = p = NULL;

                if ((k = fscanf(proc_self_mountinfo,
                                "%*s "       /* (1) mount id */
                                "%*s "       /* (2) parent id */
                                "%*s "       /* (3) major:minor */
                                "%ms "       /* (4) root */
                                "%ms "       /* (5) mount point */
                                "%*s"        /* (6) mount options */
                                "%*[^-]"     /* (7) optional fields */
                                "- "         /* (8) separator */
                                "%*s "       /* (9) file system type */
                                "%*s"        /* (10) mount source */
                                "%*s"        /* (11) mount options 2 */
                                "%*[^\n]",   /* some rubbish at the end */
                                &root,
                                &path)) != 2) {
                        if (k == EOF)
                                break;

                        log_warning("Failed to parse /proc/self/mountinfo:%u.", i);

                        free(path);
                        continue;
                }

                /* If we encounter a bind mount, don't try to remount
                 * the source dir too early */
                if (!streq(root, "/"))
                        skip_ro = true;

                free(root);

                p = cunescape(path);
                free(path);

                if (!p) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (mount_point_is_api(p) || mount_point_ignore(p)) {
                        free(p);
                        continue;
                }

                if (!(m = new0(MountPoint, 1))) {
                        free(p);
                        r = -ENOMEM;
                        goto finish;
                }

                m->path = p;
                m->skip_ro = skip_ro;
                LIST_PREPEND(MountPoint, mount_point, *head, m);
        }

        r = 0;

finish:
        fclose(proc_self_mountinfo);

        return r;
}

static int swap_list_get(MountPoint **head) {
        FILE *proc_swaps;
        unsigned int i;
        int r;

        assert(head);

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

                if (!(swap = new0(MountPoint, 1))) {
                        free(d);
                        r = -ENOMEM;
                        goto finish;
                }

                swap->path = d;
                LIST_PREPEND(MountPoint, mount_point, *head, swap);
        }

        r = 0;

finish:
        fclose(proc_swaps);

        return r;
}

static int loopback_list_get(MountPoint **head) {
        int r;
        struct udev *udev;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(head);

        if (!(udev = udev_new())) {
                r = -ENOMEM;
                goto finish;
        }

        if (!(e = udev_enumerate_new(udev))) {
                r = -ENOMEM;
                goto finish;
        }

        if (udev_enumerate_add_match_subsystem(e, "block") < 0 ||
            udev_enumerate_add_match_sysname(e, "loop*") < 0) {
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

                if (!(dn = udev_device_get_devnode(d))) {
                        udev_device_unref(d);
                        continue;
                }

                loop = strdup(dn);
                udev_device_unref(d);

                if (!loop) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(lb = new0(MountPoint, 1))) {
                        free(loop);
                        r = -ENOMEM;
                        goto finish;
                }

                lb->path = loop;
                LIST_PREPEND(MountPoint, mount_point, *head, lb);
        }

        r = 0;

finish:
        if (e)
                udev_enumerate_unref(e);

        if (udev)
                udev_unref(udev);

        return r;
}

static int dm_list_get(MountPoint **head) {
        int r;
        struct udev *udev;
        struct udev_enumerate *e = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;

        assert(head);

        if (!(udev = udev_new())) {
                r = -ENOMEM;
                goto finish;
        }

        if (!(e = udev_enumerate_new(udev))) {
                r = -ENOMEM;
                goto finish;
        }

        if (udev_enumerate_add_match_subsystem(e, "block") < 0 ||
            udev_enumerate_add_match_sysname(e, "dm-*") < 0) {
                r = -EIO;
                goto finish;
        }

        if (udev_enumerate_scan_devices(e) < 0) {
                r = -EIO;
                goto finish;
        }

        first = udev_enumerate_get_list_entry(e);

        udev_list_entry_foreach(item, first) {
                MountPoint *m;
                struct udev_device *d;
                dev_t devnum;
                char *node;
                const char *dn;

                if (!(d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item)))) {
                        r = -ENOMEM;
                        goto finish;
                }

                devnum = udev_device_get_devnum(d);
                dn = udev_device_get_devnode(d);

                if (major(devnum) == 0 || !dn) {
                        udev_device_unref(d);
                        continue;
                }

                node = strdup(dn);
                udev_device_unref(d);

                if (!node) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (!(m = new(MountPoint, 1))) {
                        free(node);
                        r = -ENOMEM;
                        goto finish;
                }

                m->path = node;
                m->devnum = devnum;
                LIST_PREPEND(MountPoint, mount_point, *head, m);
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
                return errno == ENOENT ? 0 : -errno;

        r = ioctl(fd, LOOP_CLR_FD, 0);
        close_nointr_nofail(fd);

        if (r >= 0)
                return 1;

        /* ENXIO: not bound, so no error */
        if (errno == ENXIO)
                return 0;

        return -errno;
}

static int delete_dm(dev_t devnum) {
        int fd, r;
        struct dm_ioctl dm;

        assert(major(devnum) != 0);

        if ((fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC)) < 0)
                return -errno;

        zero(dm);
        dm.version[0] = DM_VERSION_MAJOR;
        dm.version[1] = DM_VERSION_MINOR;
        dm.version[2] = DM_VERSION_PATCHLEVEL;

        dm.data_size = sizeof(dm);
        dm.dev = devnum;

        r = ioctl(fd, DM_DEV_REMOVE, &dm);
        close_nointr_nofail(fd);

        return r >= 0 ? 0 : -errno;
}

static int mount_points_list_umount(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0;

        assert(head);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {
                if (streq(m->path, "/")) {
                        n_failed++;
                        continue;
                }

                /* Trying to umount. Forcing to umount if busy (only for NFS mounts) */
                if (umount2(m->path, MNT_FORCE) == 0) {
                        if (changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not unmount %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

static int mount_points_list_remount_read_only(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0;

        assert(head);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {

                if (m->skip_ro) {
                        n_failed++;
                        continue;
                }

                /* Trying to remount read-only */
                if (mount(NULL, m->path, NULL, MS_MGC_VAL|MS_REMOUNT|MS_RDONLY, NULL) == 0) {
                        if (changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not remount as read-only %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

static int swap_points_list_off(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0;

        assert(head);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {
                if (swapoff(m->path) == 0) {
                        if (changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not deactivate swap %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

static int loopback_points_list_detach(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0, k;
        struct stat root_st;

        assert(head);

        k = lstat("/", &root_st);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {
                int r;
                struct stat loopback_st;

                if (k >= 0 &&
                    major(root_st.st_dev) != 0 &&
                    lstat(m->path, &loopback_st) >= 0 &&
                    root_st.st_dev == loopback_st.st_rdev) {
                        n_failed ++;
                        continue;
                }

                if ((r = delete_loopback(m->path)) >= 0) {

                        if (r > 0 && changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not delete loopback %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

static int dm_points_list_detach(MountPoint **head, bool *changed) {
        MountPoint *m, *n;
        int n_failed = 0, k;
        struct stat root_st;

        assert(head);

        k = lstat("/", &root_st);

        LIST_FOREACH_SAFE(mount_point, m, n, *head) {
                int r;

                if (k >= 0 &&
                    major(root_st.st_dev) != 0 &&
                    root_st.st_dev == m->devnum) {
                        n_failed ++;
                        continue;
                }

                if ((r = delete_dm(m->devnum)) >= 0) {

                        if (r > 0 && changed)
                                *changed = true;

                        mount_point_free(head, m);
                } else {
                        log_warning("Could not delete dm %s: %m", m->path);
                        n_failed++;
                }
        }

        return n_failed;
}

int umount_all(bool *changed) {
        int r;
        LIST_HEAD(MountPoint, mp_list_head);

        LIST_HEAD_INIT(MountPoint, mp_list_head);

        r = mount_points_list_get(&mp_list_head);
        if (r < 0)
                goto end;

        r = mount_points_list_umount(&mp_list_head, changed);
        if (r <= 0)
                goto end;

        r = mount_points_list_remount_read_only(&mp_list_head, changed);

  end:
        mount_points_list_free(&mp_list_head);

        return r;
}

int swapoff_all(bool *changed) {
        int r;
        LIST_HEAD(MountPoint, swap_list_head);

        LIST_HEAD_INIT(MountPoint, swap_list_head);

        r = swap_list_get(&swap_list_head);
        if (r < 0)
                goto end;

        r = swap_points_list_off(&swap_list_head, changed);

  end:
        mount_points_list_free(&swap_list_head);

        return r;
}

int loopback_detach_all(bool *changed) {
        int r;
        LIST_HEAD(MountPoint, loopback_list_head);

        LIST_HEAD_INIT(MountPoint, loopback_list_head);

        r = loopback_list_get(&loopback_list_head);
        if (r < 0)
                goto end;

        r = loopback_points_list_detach(&loopback_list_head, changed);

  end:
        mount_points_list_free(&loopback_list_head);

        return r;
}

int dm_detach_all(bool *changed) {
        int r;
        LIST_HEAD(MountPoint, dm_list_head);

        LIST_HEAD_INIT(MountPoint, dm_list_head);

        r = dm_list_get(&dm_list_head);
        if (r < 0)
                goto end;

        r = dm_points_list_detach(&dm_list_head, changed);

  end:
        mount_points_list_free(&dm_list_head);

        return r;
}
