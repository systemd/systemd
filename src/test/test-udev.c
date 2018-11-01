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
#include "tests.h"
#include "udev.h"

static int fake_filesystems(void) {
        static const struct fakefs {
                const char *src;
                const char *target;
                const char *error;
                bool ignore_mount_error;
        } fakefss[] = {
                { "test/tmpfs/sys", "/sys",                    "Failed to mount test /sys",                        false },
                { "test/tmpfs/dev", "/dev",                    "Failed to mount test /dev",                        false },
                { "test/run",       "/run",                    "Failed to mount test /run",                        false },
                { "test/run",       "/etc/udev/rules.d",       "Failed to mount empty /etc/udev/rules.d",          true },
                { "test/run",       UDEVLIBEXECDIR "/rules.d", "Failed to mount empty " UDEVLIBEXECDIR "/rules.d", true },
        };
        unsigned i;

        if (unshare(CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Failed to call unshare(): %m");

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return log_error_errno(errno, "Failed to mount / as private: %m");

        for (i = 0; i < ELEMENTSOF(fakefss); i++)
                if (mount(fakefss[i].src, fakefss[i].target, NULL, MS_BIND, NULL) < 0) {
                        log_full_errno(fakefss[i].ignore_mount_error ? LOG_DEBUG : LOG_ERR, errno, "%s: %m", fakefss[i].error);
                        if (!fakefss[i].ignore_mount_error)
                                return -errno;
                }

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(udev_event_freep) struct udev_event *event = NULL;
        _cleanup_(udev_device_unrefp) struct udev_device *dev = NULL;
        _cleanup_(udev_rules_unrefp) struct udev_rules *rules = NULL;
        const char *devpath, *action;

        test_setup_logging(LOG_INFO);

        if (argc != 3) {
                log_error("This program needs two arguments, %d given", argc - 1);
                return EXIT_FAILURE;
        }

        if (fake_filesystems() < 0)
                return EXIT_FAILURE;

        log_debug("version %s", PACKAGE_VERSION);
        mac_selinux_init();

        action = argv[1];
        devpath = argv[2];

        rules = udev_rules_new(1);

        const char *syspath = strjoina("/sys", devpath);
        dev = udev_device_new_from_synthetic_event(NULL, syspath, action);
        if (!dev) {
                log_debug("unknown device '%s'", devpath);
                goto out;
        }

        assert_se(event = udev_event_new(dev, 0));

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, -1) >= 0);

        /* do what devtmpfs usually provides us */
        if (udev_device_get_devnode(dev)) {
                mode_t mode = 0600;

                if (streq(udev_device_get_subsystem(dev), "block"))
                        mode |= S_IFBLK;
                else
                        mode |= S_IFCHR;

                if (!streq(action, "remove")) {
                        (void) mkdir_parents_label(udev_device_get_devnode(dev), 0755);
                        assert_se(mknod(udev_device_get_devnode(dev), mode, udev_device_get_devnum(dev)) == 0);
                } else {
                        assert_se(unlink(udev_device_get_devnode(dev)) == 0);
                        (void) rmdir_parents(udev_device_get_devnode(dev), "/");
                }
        }

        udev_event_execute_rules(event, 3 * USEC_PER_SEC, USEC_PER_SEC, NULL, rules);
        udev_event_execute_run(event, 3 * USEC_PER_SEC, USEC_PER_SEC);
out:
        mac_selinux_finish();

        return EXIT_SUCCESS;
}
