/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 Holger Hans Peter Freyther

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
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>

#include "sd-bus.h"
#include "libudev.h"

#include "util.h"
#include "special.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-errors.h"
#include "fileio.h"
#include "udev-util.h"
#include "path-util.h"

static bool arg_skip = false;
static bool arg_force = false;
static bool arg_show_progress = false;
static const char *arg_repair = "-a";

static void start_target(const char *target) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        assert(target);

        r = bus_open_system_systemd(&bus);
        if (r < 0) {
                log_error("Failed to get D-Bus connection: %s", strerror(-r));
                return;
        }

        log_info("Running request %s/start/replace", target);

        /* Start these units only if we can replace base.target with it */
        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "StartUnitReplace",
                               &error,
                               NULL,
                               "sss", "basic.target", target, "replace");

        /* Don't print a warning if we aren't called during startup */
        if (r < 0 && !sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_JOB))
                log_error("Failed to start unit: %s", bus_error_message(&error, -r));
}

static int parse_proc_cmdline_item(const char *key, const char *value) {

        if (streq(key, "fsck.mode") && value) {

                if (streq(value, "auto"))
                        arg_force = arg_skip = false;
                else if (streq(value, "force"))
                        arg_force = true;
                else if (streq(value, "skip"))
                        arg_skip = true;
                else
                        log_warning("Invalid fsck.mode= parameter '%s'. Ignoring.", value);

        } else if (streq(key, "fsck.repair") && value) {

                if (streq(value, "preen"))
                        arg_repair = "-a";
                else if (streq(value, "yes"))
                        arg_repair = "-y";
                else if (streq(value, "no"))
                        arg_repair = "-n";
                else
                        log_warning("Invalid fsck.repair= parameter '%s'. Ignoring.", value);
        }

#ifdef HAVE_SYSV_COMPAT
        else if (streq(key, "fastboot") && !value) {
                log_warning("Please pass 'fsck.mode=skip' rather than 'fastboot' on the kernel command line.");
                arg_skip = true;

        } else if (streq(key, "forcefsck") && !value) {
                log_warning("Please pass 'fsck.mode=force' rather than 'forcefsck' on the kernel command line.");
                arg_force = true;
        }
#endif

        return 0;
}

static void test_files(void) {

#ifdef HAVE_SYSV_COMPAT
        if (access("/fastboot", F_OK) >= 0) {
                log_error("Please pass 'fsck.mode=skip' on the kernel command line rather than creating /fastboot on the root file system.");
                arg_skip = true;
        }

        if (access("/forcefsck", F_OK) >= 0) {
                log_error("Please pass 'fsck.mode=force' on the kernel command line rather than creating /forcefsck on the root file system.");
                arg_force = true;
        }
#endif

        if (access("/run/systemd/show-status", F_OK) >= 0 || plymouth_running())
                arg_show_progress = true;
}

static double percent(int pass, unsigned long cur, unsigned long max) {
        /* Values stolen from e2fsck */

        static const int pass_table[] = {
                0, 70, 90, 92, 95, 100
        };

        if (pass <= 0)
                return 0.0;

        if ((unsigned) pass >= ELEMENTSOF(pass_table) || max == 0)
                return 100.0;

        return (double) pass_table[pass-1] +
                ((double) pass_table[pass] - (double) pass_table[pass-1]) *
                (double) cur / (double) max;
}

static int process_progress(int fd) {
        _cleanup_fclose_ FILE *console = NULL, *f = NULL;
        usec_t last = 0;
        bool locked = false;
        int clear = 0;

        f = fdopen(fd, "r");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        console = fopen("/dev/console", "we");
        if (!console)
                return -ENOMEM;

        while (!feof(f)) {
                int pass, m;
                unsigned long cur, max;
                _cleanup_free_ char *device = NULL;
                double p;
                usec_t t;

                if (fscanf(f, "%i %lu %lu %ms", &pass, &cur, &max, &device) != 4)
                        break;

                /* Only show one progress counter at max */
                if (!locked) {
                        if (flock(fileno(console), LOCK_EX|LOCK_NB) < 0)
                                continue;

                        locked = true;
                }

                /* Only update once every 50ms */
                t = now(CLOCK_MONOTONIC);
                if (last + 50 * USEC_PER_MSEC > t)
                        continue;

                last = t;

                p = percent(pass, cur, max);
                fprintf(console, "\r%s: fsck %3.1f%% complete...\r%n", device, p, &m);
                fflush(console);

                if (m > clear)
                        clear = m;
        }

        if (clear > 0) {
                unsigned j;

                fputc('\r', console);
                for (j = 0; j < (unsigned) clear; j++)
                        fputc(' ', console);
                fputc('\r', console);
                fflush(console);
        }

        return 0;
}

int main(int argc, char *argv[]) {
        const char *cmdline[9];
        int i = 0, r = EXIT_FAILURE, q;
        pid_t pid;
        siginfo_t status;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_udev_device_unref_ struct udev_device *udev_device = NULL;
        const char *device, *type;
        bool root_directory;
        int progress_pipe[2] = { -1, -1 };
        char dash_c[2+10+1];
        struct stat st;

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        parse_proc_cmdline(parse_proc_cmdline_item);
        test_files();

        if (!arg_force && arg_skip)
                return 0;

        udev = udev_new();
        if (!udev) {
                log_oom();
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                device = argv[1];
                root_directory = false;

                if (stat(device, &st) < 0) {
                        log_error("Failed to stat '%s': %m", device);
                        return EXIT_FAILURE;
                }

                udev_device = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
                if (!udev_device) {
                        log_error("Failed to detect device %s", device);
                        return EXIT_FAILURE;
                }
        } else {
                struct timespec times[2];

                /* Find root device */

                if (stat("/", &st) < 0) {
                        log_error("Failed to stat() the root directory: %m");
                        return EXIT_FAILURE;
                }

                /* Virtual root devices don't need an fsck */
                if (major(st.st_dev) == 0)
                        return EXIT_SUCCESS;

                /* check if we are already writable */
                times[0] = st.st_atim;
                times[1] = st.st_mtim;
                if (utimensat(AT_FDCWD, "/", times, 0) == 0) {
                        log_info("Root directory is writable, skipping check.");
                        return EXIT_SUCCESS;
                }

                udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev);
                if (!udev_device) {
                        log_error("Failed to detect root device.");
                        return EXIT_FAILURE;
                }

                device = udev_device_get_devnode(udev_device);
                if (!device) {
                        log_error("Failed to detect device node of root directory.");
                        return EXIT_FAILURE;
                }

                root_directory = true;
        }

        type = udev_device_get_property_value(udev_device, "ID_FS_TYPE");
        if (type) {
                r = fsck_exists(type);
                if (r == -ENOENT) {
                        log_info("fsck.%s doesn't exist, not checking file system on %s", type, device);
                        return EXIT_SUCCESS;
                } else if (r < 0)
                        log_warning("fsck.%s cannot be used for %s: %s", type, device, strerror(-r));
        }

        if (arg_show_progress)
                if (pipe(progress_pipe) < 0) {
                        log_error("pipe(): %m");
                        return EXIT_FAILURE;
                }

        cmdline[i++] = "/sbin/fsck";
        cmdline[i++] =  arg_repair;
        cmdline[i++] = "-T";

        /*
         * Disable locking which conflict with udev's event
         * ownershipi, until util-linux moves the flock
         * synchronization file which prevents multiple fsck running
         * on the same rotationg media, from the disk device
         * node to a privately owned regular file.
         *
         * https://bugs.freedesktop.org/show_bug.cgi?id=79576#c5
         *
         * cmdline[i++] = "-l";
         */

        if (!root_directory)
                cmdline[i++] = "-M";

        if (arg_force)
                cmdline[i++] = "-f";

        if (progress_pipe[1] >= 0) {
                snprintf(dash_c, sizeof(dash_c), "-C%i", progress_pipe[1]);
                char_array_0(dash_c);
                cmdline[i++] = dash_c;
        }

        cmdline[i++] = device;
        cmdline[i++] = NULL;

        pid = fork();
        if (pid < 0) {
                log_error("fork(): %m");
                goto finish;
        } else if (pid == 0) {
                /* Child */
                if (progress_pipe[0] >= 0)
                        safe_close(progress_pipe[0]);
                execv(cmdline[0], (char**) cmdline);
                _exit(8); /* Operational error */
        }

        progress_pipe[1] = safe_close(progress_pipe[1]);

        if (progress_pipe[0] >= 0) {
                process_progress(progress_pipe[0]);
                progress_pipe[0] = -1;
        }

        q = wait_for_terminate(pid, &status);
        if (q < 0) {
                log_error("waitid(): %s", strerror(-q));
                goto finish;
        }

        if (status.si_code != CLD_EXITED || (status.si_status & ~1)) {

                if (status.si_code == CLD_KILLED || status.si_code == CLD_DUMPED)
                        log_error("fsck terminated by signal %s.", signal_to_string(status.si_status));
                else if (status.si_code == CLD_EXITED)
                        log_error("fsck failed with error code %i.", status.si_status);
                else
                        log_error("fsck failed due to unknown reason.");

                if (status.si_code == CLD_EXITED && (status.si_status & 2) && root_directory)
                        /* System should be rebooted. */
                        start_target(SPECIAL_REBOOT_TARGET);
                else if (status.si_code == CLD_EXITED && (status.si_status & 6))
                        /* Some other problem */
                        start_target(SPECIAL_EMERGENCY_TARGET);
                else {
                        r = EXIT_SUCCESS;
                        log_warning("Ignoring error.");
                }

        } else
                r = EXIT_SUCCESS;

        if (status.si_code == CLD_EXITED && (status.si_status & 1))
                touch("/run/systemd/quotacheck");

finish:
        safe_close_pair(progress_pipe);

        return r;
}
