/***
  This file is part of systemd.

  Copyright 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
  Copyright 2004-2012 Kay Sievers <kay@vrfy.org>

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
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "fs-util.h"
#include "log.h"
#include "missing.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "udev-util.h"
#include "udev.h"

static int fake_filesystems(void) {
        static const struct fakefs {
                const char *src;
                const char *target;
                const char *error;
                bool ignore_mount_error;
        } fakefss[] = {
                { "test/tmpfs/sys", "/sys",                    "failed to mount test /sys",                        false },
                { "test/tmpfs/dev", "/dev",                    "failed to mount test /dev",                        false },
                { "test/run",       "/run",                    "failed to mount test /run",                        false },
                { "test/run",       "/etc/udev/rules.d",       "failed to mount empty /etc/udev/rules.d",          true },
                { "test/run",       UDEVLIBEXECDIR "/rules.d", "failed to mount empty " UDEVLIBEXECDIR "/rules.d", true },
        };
        unsigned int i;

        if (unshare(CLONE_NEWNS) < 0)
                return log_error_errno(errno, "failed to call unshare(): %m");

        if (mount(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL) < 0)
                return log_error_errno(errno, "failed to mount / as private: %m");

        for (i = 0; i < ELEMENTSOF(fakefss); i++) {
                if (mount(fakefss[i].src, fakefss[i].target, NULL, MS_BIND, NULL) < 0) {
                        log_full_errno(fakefss[i].ignore_mount_error ? LOG_DEBUG : LOG_ERR, errno, "%s: %m", fakefss[i].error);
                        if (!fakefss[i].ignore_mount_error)
                                return -errno;
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *devpath;
        const char *action;
        int err;

        log_parse_environment();
        log_open();

        err = fake_filesystems();
        if (err < 0)
                return EXIT_FAILURE;

        udev = udev_new();
        if (udev == NULL)
                return EXIT_FAILURE;

        log_debug("version %s", PACKAGE_VERSION);
        mac_selinux_init();

        action = argv[1];
        if (action == NULL) {
                log_error("action missing");
                goto out;
        }

        devpath = argv[2];
        if (devpath == NULL) {
                log_error("devpath missing");
                goto out;
        }

        rules = udev_rules_new(udev, 1);

        strscpyl(syspath, sizeof(syspath), "/sys", devpath, NULL);
        dev = udev_device_new_from_synthetic_event(udev, syspath, action);
        if (dev == NULL) {
                log_debug("unknown device '%s'", devpath);
                goto out;
        }

        event = udev_event_new(dev);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, -1) >= 0);

        /* do what devtmpfs usually provides us */
        if (udev_device_get_devnode(dev) != NULL) {
                mode_t mode = 0600;

                if (streq(udev_device_get_subsystem(dev), "block"))
                        mode |= S_IFBLK;
                else
                        mode |= S_IFCHR;

                if (!streq(action, "remove")) {
                        mkdir_parents_label(udev_device_get_devnode(dev), 0755);
                        mknod(udev_device_get_devnode(dev), mode, udev_device_get_devnum(dev));
                } else {
                        unlink(udev_device_get_devnode(dev));
                        rmdir_parents(udev_device_get_devnode(dev), "/");
                }
        }

        udev_event_execute_rules(event,
                                 3 * USEC_PER_SEC, USEC_PER_SEC,
                                 NULL,
                                 rules);
        udev_event_execute_run(event,
                               3 * USEC_PER_SEC, USEC_PER_SEC);
out:
        mac_selinux_finish();

        return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
