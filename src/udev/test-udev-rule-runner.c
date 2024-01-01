/* SPDX-License-Identifier: LGPL-2.1-or-later */
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

#include "device-private.h"
#include "device-util.h"
#include "fs-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "tests.h"
#include "udev-event.h"
#include "udev-spawn.h"
#include "version.h"

static int device_new_from_synthetic_event(sd_device **ret, const char *syspath, const char *action) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        sd_device_action_t a;
        int r;

        assert(ret);
        assert(syspath);
        assert(action);

        a = device_action_from_string(action);
        if (a < 0)
                return a;

        r = sd_device_new_from_syspath(&dev, syspath);
        if (r < 0)
                return r;

        r = device_read_uevent_file(dev);
        if (r < 0)
                return r;

        r = device_set_action(dev, a);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dev);
        return 0;
}

static int fake_filesystems(void) {
        static const struct fakefs {
                const char *src;
                const char *target;
                const char *error;
                bool ignore_mount_error;
        } fakefss[] = {
                { "tmpfs/sys", "/sys",                    "Failed to mount test /sys",                        false },
                { "tmpfs/dev", "/dev",                    "Failed to mount test /dev",                        false },
                { "run",       "/run",                    "Failed to mount test /run",                        false },
                { "run",       "/etc/udev/rules.d",       "Failed to mount empty /etc/udev/rules.d",          true },
                { "run",       UDEVLIBEXECDIR "/rules.d", "Failed to mount empty " UDEVLIBEXECDIR "/rules.d", true },
        };
        int r;

        r = detach_mount_namespace();
        if (r < 0)
                return log_error_errno(r, "Failed to detach mount namespace: %m");

        for (size_t i = 0; i < ELEMENTSOF(fakefss); i++) {
                r = mount_nofollow_verbose(fakefss[i].ignore_mount_error ? LOG_NOTICE : LOG_ERR,
                                           fakefss[i].src, fakefss[i].target, NULL, MS_BIND, NULL);
                if (r < 0 && !fakefss[i].ignore_mount_error)
                        return r;
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

        if (!IN_SET(argc, 2, 3, 4))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program needs between one and three arguments, %d given", argc - 1);

        r = fake_filesystems();
        if (r < 0)
                return r;

        /* Let's make sure the test runs with selinux assumed disabled. */
#if HAVE_SELINUX
        fini_selinuxmnt();
#endif
        mac_selinux_retest();

        if (argc == 2) {
                if (!streq(argv[1], "check"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unknown argument: %s", argv[1]);

                return 0;
        }

        log_debug("version %s", GIT_VERSION);

        r = mac_init();
        if (r < 0)
                return r;

        action = argv[1];
        devpath = argv[2];

        if (argv[3]) {
                unsigned us;

                r = safe_atou(argv[3], &us);
                if (r < 0)
                        return log_error_errno(r, "Invalid delay '%s': %m", argv[3]);
                usleep_safe(us);
        }

        assert_se(udev_rules_load(&rules, RESOLVE_NAME_EARLY) == 0);

        const char *syspath = strjoina("/sys", devpath);
        r = device_new_from_synthetic_event(&dev, syspath, action);
        if (r < 0)
                return log_debug_errno(r, "Failed to open device '%s'", devpath);

        assert_se(event = udev_event_new(dev, NULL));

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGTERM, SIGINT, SIGHUP, SIGCHLD, -1) >= 0);

        /* do what devtmpfs usually provides us */
        if (sd_device_get_devname(dev, &devname) >= 0) {
                mode_t mode = 0600;

                if (device_in_subsystem(dev, "block"))
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
                        (void) rmdir_parents(devname, "/dev");
                }
        }

        udev_event_execute_rules(event, rules);
        udev_event_execute_run(event);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
