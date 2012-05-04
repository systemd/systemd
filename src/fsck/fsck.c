/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <libudev.h>
#include <dbus/dbus.h>

#include "util.h"
#include "dbus-common.h"
#include "special.h"
#include "bus-errors.h"
#include "virt.h"
#include "fileio.h"

static bool arg_skip = false;
static bool arg_force = false;
static bool arg_show_progress = false;

static void start_target(const char *target) {
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        const char *mode = "replace", *basic_target = "basic.target";
        DBusConnection *bus = NULL;

        assert(target);

        dbus_error_init(&error);

        if (bus_connect(DBUS_BUS_SYSTEM, &bus, NULL, &error) < 0) {
                log_error("Failed to get D-Bus connection: %s", bus_error_message(&error));
                goto finish;
        }

        log_info("Running request %s/start/%s", target, mode);

        if (!(m = dbus_message_new_method_call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnitReplace"))) {
                log_error("Could not allocate message.");
                goto finish;
        }

        /* Start these units only if we can replace base.target with it */

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &basic_target,
                                      DBUS_TYPE_STRING, &target,
                                      DBUS_TYPE_STRING, &mode,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not attach target and flag information to message.");
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(bus, m, -1, &error))) {

                /* Don't print a warning if we aren't called during
                 * startup */
                if (!dbus_error_has_name(&error, BUS_ERROR_NO_SUCH_JOB))
                        log_error("Failed to start unit: %s", bus_error_message(&error));

                goto finish;
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        if (bus) {
                dbus_connection_flush(bus);
                dbus_connection_close(bus);
                dbus_connection_unref(bus);
        }

        dbus_error_free(&error);
}

static int parse_proc_cmdline(void) {
        char *line, *w, *state;
        int r;
        size_t l;

        if (detect_container(NULL) > 0)
                return 0;

        r = read_one_line_file("/proc/cmdline", &line);
        if (r < 0) {
                log_warning("Failed to read /proc/cmdline, ignoring: %s", strerror(-r));
                return 0;
        }

        FOREACH_WORD_QUOTED(w, l, line, state) {

                if (strneq(w, "fsck.mode=auto", l))
                        arg_force = arg_skip = false;
                else if (strneq(w, "fsck.mode=force", l))
                        arg_force = true;
                else if (strneq(w, "fsck.mode=skip", l))
                        arg_skip = true;
                else if (startswith(w, "fsck"))
                        log_warning("Invalid fsck parameter. Ignoring.");
#ifdef HAVE_SYSV_COMPAT
                else if (strneq(w, "fastboot", l)) {
                        log_error("Please pass 'fsck.mode=skip' rather than 'fastboot' on the kernel command line.");
                        arg_skip = true;
                } else if (strneq(w, "forcefsck", l)) {
                        log_error("Please pass 'fsck.mode=force' rather than 'forcefsck' on the kernel command line.");
                        arg_force = true;
                }
#endif
        }

        free(line);
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
        FILE *f, *console;
        usec_t last = 0;
        bool locked = false;
        int clear = 0;

        f = fdopen(fd, "r");
        if (!f) {
                close_nointr_nofail(fd);
                return -errno;
        }

        console = fopen("/dev/console", "w");
        if (!console) {
                fclose(f);
                return -ENOMEM;
        }

        while (!feof(f)) {
                int pass, m;
                unsigned long cur, max;
                char *device;
                double p;
                usec_t t;

                if (fscanf(f, "%i %lu %lu %ms", &pass, &cur, &max, &device) != 4)
                        break;

                /* Only show one progress counter at max */
                if (!locked) {
                        if (flock(fileno(console), LOCK_EX|LOCK_NB) < 0) {
                                free(device);
                                continue;
                        }

                        locked = true;
                }

                /* Only update once every 50ms */
                t = now(CLOCK_MONOTONIC);
                if (last + 50 * USEC_PER_MSEC > t)  {
                        free(device);
                        continue;
                }

                last = t;

                p = percent(pass, cur, max);
                fprintf(console, "\r%s: fsck %3.1f%% complete...\r%n", device, p, &m);
                fflush(console);

                free(device);

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

        fclose(f);
        fclose(console);
        return 0;
}

int main(int argc, char *argv[]) {
        const char *cmdline[9];
        int i = 0, r = EXIT_FAILURE, q;
        pid_t pid;
        siginfo_t status;
        struct udev *udev = NULL;
        struct udev_device *udev_device = NULL;
        const char *device;
        bool root_directory;
        int progress_pipe[2] = { -1, -1 };
        char dash_c[2+10+1];

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        parse_proc_cmdline();
        test_files();

        if (!arg_force && arg_skip)
                return 0;

        if (argc > 1) {
                device = argv[1];
                root_directory = false;
        } else {
                struct stat st;
                struct timespec times[2];

                /* Find root device */

                if (stat("/", &st) < 0) {
                        log_error("Failed to stat() the root directory: %m");
                        goto finish;
                }

                /* Virtual root devices don't need an fsck */
                if (major(st.st_dev) == 0)
                        return 0;

                /* check if we are already writable */
                times[0] = st.st_atim;
                times[1] = st.st_mtim;
                if (utimensat(AT_FDCWD, "/", times, 0) == 0) {
                        log_info("Root directory is writable, skipping check.");
                        return 0;
                }

                if (!(udev = udev_new())) {
                        log_oom();
                        goto finish;
                }

                if (!(udev_device = udev_device_new_from_devnum(udev, 'b', st.st_dev))) {
                        log_error("Failed to detect root device.");
                        goto finish;
                }

                if (!(device = udev_device_get_devnode(udev_device))) {
                        log_error("Failed to detect device node of root directory.");
                        goto finish;
                }

                root_directory = true;
        }

        if (arg_show_progress)
                if (pipe(progress_pipe) < 0) {
                        log_error("pipe(): %m");
                        goto finish;
                }

        cmdline[i++] = "/sbin/fsck";
        cmdline[i++] = "-a";
        cmdline[i++] = "-T";
        cmdline[i++] = "-l";

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
                        close_nointr_nofail(progress_pipe[0]);
                execv(cmdline[0], (char**) cmdline);
                _exit(8); /* Operational error */
        }

        if (progress_pipe[1] >= 0) {
                close_nointr_nofail(progress_pipe[1]);
                progress_pipe[1] = -1;
        }

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
        if (udev_device)
                udev_device_unref(udev_device);

        if (udev)
                udev_unref(udev);

        close_pipe(progress_pipe);

        return r;
}
