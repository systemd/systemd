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

#include "build.h"
#include "device-private.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "missing.h"
#include "mkdir.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "tests.h"
#include "udev-event.h"

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

static int run(int argc, char *argv[]) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_(udev_event_freep) UdevEvent *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *devpath, *devname, *action;
        int r;

        test_setup_logging(LOG_INFO);

        if (!IN_SET(argc, 2, 3)) {
                log_error("This program needs one or two arguments, %d given", argc - 1);
                return -EINVAL;
        }

        r = fake_filesystems();
        if (r < 0)
                return r;

        if (argc == 2) {
                if (!streq(argv[1], "check")) {
                        log_error("Unknown argument: %s", argv[1]);
                        return -EINVAL;
                }

                return 0;
        }

        log_debug("version %s", GIT_VERSION);
        mac_selinux_init();

        action = argv[1];
        devpath = argv[2];

        assert_se(udev_rules_new(&rules, RESOLVE_NAME_EARLY) == 0);

        const char *syspath = strjoina("/sys", devpath);
        r = device_new_from_synthetic_event(&dev, syspath, action);
        if (r < 0)
                return log_debug_errno(r, "Failed to open device '%s'", devpath);

        assert_se(event = udev_event_new(dev, 0, NULL));

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, -1) >= 0);

        /* do what devtmpfs usually provides us */
        if (sd_device_get_devname(dev, &devname) >= 0) {
                const char *subsystem;
                mode_t mode = 0600;

                if (sd_device_get_subsystem(dev, &subsystem) >= 0 && streq(subsystem, "block"))
                        mode |= S_IFBLK;
                else
                        mode |= S_IFCHR;

                if (!streq(action, "remove")) {
                        dev_t devnum = makedev(0, 0);

                        (void) mkdir_parents_label(devname, 0755);
                        (void) sd_device_get_devnum(dev, &devnum);
                        if (mknod(devname, mode, devnum) < 0)
                                return log_error_errno(errno, "mknod() failed for '%s': %m", devname);
                } else {
                        if (unlink(devname) < 0)
                                return log_error_errno(errno, "unlink('%s') failed: %m", devname);
                        (void) rmdir_parents(devname, "/");
                }
        }

        udev_event_execute_rules(event, 3 * USEC_PER_SEC, NULL, rules);
        udev_event_execute_run(event, 3 * USEC_PER_SEC);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
