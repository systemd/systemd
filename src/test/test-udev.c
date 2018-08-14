/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
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

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
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
        _cleanup_(udev_unrefp) struct udev *udev = NULL;
        _cleanup_(udev_event_unrefp) struct udev_event *event = NULL;
        _cleanup_(udev_device_unrefp) struct udev_device *dev = NULL;
        _cleanup_(udev_rules_unrefp) struct udev_rules *rules = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *devpath;
        const char *action;
        int r;

        log_parse_environment();
        log_open();

        r = fake_filesystems();
        if (r < 0)
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
        r = udev_device_new_from_synthetic_event(syspath, action, &dev);
        if (r < 0) {
                log_debug_errno(r, "unknown device '%s': %m", devpath);
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

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
