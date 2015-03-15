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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/signalfd.h>

#include "missing.h"
#include "selinux-util.h"
#include "udev.h"
#include "udev-util.h"

static int fake_filesystems(void) {
        static const struct fakefs {
                const char *src;
                const char *target;
                const char *error;
        } fakefss[] = {
                { "test/sys", "/sys",                   "failed to mount test /sys" },
                { "test/dev", "/dev",                   "failed to mount test /dev" },
                { "test/run", "/run",                   "failed to mount test /run" },
                { "test/run", "/etc/udev/rules.d",      "failed to mount empty /etc/udev/rules.d" },
                { "test/run", "/usr/lib/udev/rules.d",  "failed to mount empty /usr/lib/udev/rules.d" },
        };
        unsigned int i;
        int err;

        err = unshare(CLONE_NEWNS);
        if (err < 0) {
                err = -errno;
                fprintf(stderr, "failed to call unshare(): %m\n");
                goto out;
        }

        if (mount(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL) < 0) {
                err = -errno;
                fprintf(stderr, "failed to mount / as private: %m\n");
                goto out;
        }

        for (i = 0; i < ELEMENTSOF(fakefss); i++) {
                err = mount(fakefss[i].src, fakefss[i].target, NULL, MS_BIND, NULL);
                if (err < 0) {
                        err = -errno;
                        fprintf(stderr, "%s %m", fakefss[i].error);
                        return err;
                }
        }
out:
        return err;
}

int main(int argc, char *argv[]) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_event_unref_ struct udev_event *event = NULL;
        _cleanup_udev_device_unref_ struct udev_device *dev = NULL;
        _cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
        char syspath[UTIL_PATH_SIZE];
        const char *devpath;
        const char *action;
        sigset_t mask, sigmask_orig;
        int err;

        err = fake_filesystems();
        if (err < 0)
                return EXIT_FAILURE;

        udev = udev_new();
        if (udev == NULL)
                return EXIT_FAILURE;

        log_debug("version %s", VERSION);
        mac_selinux_init("/dev");

        sigprocmask(SIG_SETMASK, NULL, &sigmask_orig);

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

        sigfillset(&mask);
        sigprocmask(SIG_SETMASK, &mask, &sigmask_orig);
        event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK|SFD_CLOEXEC);
        if (event->fd_signal < 0) {
                fprintf(stderr, "error creating signalfd\n");
                goto out;
        }

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
                                 rules,
                                 &sigmask_orig);
        udev_event_execute_run(event,
                               3 * USEC_PER_SEC, USEC_PER_SEC,
                               NULL);
out:
        if (event != NULL && event->fd_signal >= 0)
                close(event->fd_signal);
        mac_selinux_finish();

        return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
