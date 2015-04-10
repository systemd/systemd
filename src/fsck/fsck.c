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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "util.h"
#include "process-util.h"
#include "special.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-common-errors.h"
#include "device-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "fsckd/fsckd.h"

static bool arg_skip = false;
static bool arg_force = false;
static const char *arg_repair = "-a";

static void start_target(const char *target) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        int r;

        assert(target);

        r = bus_open_system_systemd(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to get D-Bus connection: %m");
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

}

static int process_progress(int fd, pid_t fsck_pid, dev_t device_num) {
        _cleanup_fclose_ FILE *f = NULL;
        usec_t last = 0;
        _cleanup_close_ int fsckd_fd = -1;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = FSCKD_SOCKET_PATH,
        };

        fsckd_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fsckd_fd < 0)
                return log_warning_errno(errno, "Cannot open fsckd socket, we won't report fsck progress: %m");
        if (connect(fsckd_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0)
                return log_warning_errno(errno, "Cannot connect to fsckd socket, we won't report fsck progress: %m");

        f = fdopen(fd, "r");
        if (!f)
                return log_warning_errno(errno, "Cannot connect to fsck, we won't report fsck progress: %m");

        while (!feof(f)) {
                int pass;
                size_t buflen;
                size_t cur, max;
                ssize_t r;
                usec_t t;
                _cleanup_free_ char *device = NULL;
                FsckProgress progress;
                FsckdMessage fsckd_message;

                if (fscanf(f, "%i %zu %zu %ms", &pass, &cur, &max, &device) != 4)
                        break;

                /* Only update once every 50ms */
                t = now(CLOCK_MONOTONIC);
                if (last + 50 * USEC_PER_MSEC > t)
                        continue;

                last = t;

                /* send progress to fsckd */
                progress.devnum = device_num;
                progress.cur = cur;
                progress.max = max;
                progress.pass = pass;

                r = send(fsckd_fd, &progress, sizeof(FsckProgress), 0);
                if (r < 0 || (size_t) r < sizeof(FsckProgress))
                        log_warning_errno(errno, "Cannot communicate fsck progress to fsckd: %m");

                /* get fsckd requests, only read when we have coherent size data */
                r = ioctl(fsckd_fd, FIONREAD, &buflen);
                if (r == 0 && (size_t) buflen >= sizeof(FsckdMessage)) {
                        r = recv(fsckd_fd, &fsckd_message, sizeof(FsckdMessage), 0);
                        if (r > 0 && fsckd_message.cancel == 1) {
                                log_info("Request to cancel fsck from fsckd");
                                kill(fsck_pid, SIGTERM);
                        }
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        const char *cmdline[9];
        int i = 0, r = EXIT_FAILURE, q;
        pid_t pid;
        int progress_rc;
        siginfo_t status;
        _cleanup_device_unref_ sd_device *dev = NULL;
        const char *device, *type;
        bool root_directory;
        _cleanup_close_pair_ int progress_pipe[2] = { -1, -1 };
        char dash_c[sizeof("-C")-1 + DECIMAL_STR_MAX(int) + 1];
        struct stat st;

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        q = parse_proc_cmdline(parse_proc_cmdline_item);
        if (q < 0)
                log_warning_errno(q, "Failed to parse kernel command line, ignoring: %m");

        test_files();

        if (!arg_force && arg_skip) {
                r = 0;
                goto finish;
        }

        if (argc > 1) {
                device = argv[1];
                root_directory = false;

                if (stat(device, &st) < 0) {
                        r = log_error_errno(errno, "Failed to stat '%s': %m", device);
                        goto finish;
                }

                r = sd_device_new_from_devnum(&dev, 'b', st.st_rdev);
                if (r < 0) {
                        log_error_errno(r, "Failed to detect device %s: %m", device);
                        goto finish;
                }
        } else {
                struct timespec times[2];

                /* Find root device */

                if (stat("/", &st) < 0) {
                        r = log_error_errno(errno, "Failed to stat() the root directory: %m");
                        goto finish;
                }

                /* Virtual root devices don't need an fsck */
                if (major(st.st_dev) == 0) {
                        log_debug("Root directory is virtual, skipping check.");
                        r = 0;
                        goto finish;
                }

                /* check if we are already writable */
                times[0] = st.st_atim;
                times[1] = st.st_mtim;
                if (utimensat(AT_FDCWD, "/", times, 0) == 0) {
                        log_info("Root directory is writable, skipping check.");
                        r = 0;
                        goto finish;
                }

                r = sd_device_new_from_devnum(&dev, 'b', st.st_dev);
                if (r < 0) {
                        log_error_errno(r, "Failed to detect root device: %m");
                        goto finish;
                }

                r = sd_device_get_devname(dev, &device);
                if (r < 0) {
                        log_error_errno(r, "Failed to detect device node of root directory: %m");
                        r = -ENXIO;
                        goto finish;
                }

                root_directory = true;
        }

        r = sd_device_get_property_value(dev, "ID_FS_TYPE", &type);
        if (r >= 0) {
                r = fsck_exists(type);
                if (r == -ENOENT) {
                        log_info("fsck.%s doesn't exist, not checking file system on %s", type, device);
                        r = 0;
                        goto finish;
                } else if (r < 0)
                        log_warning_errno(r, "fsck.%s cannot be used for %s: %m", type, device);
        }

        if (pipe(progress_pipe) < 0) {
                r = log_error_errno(errno, "pipe(): %m");
                goto finish;
        }

        cmdline[i++] = "/sbin/fsck";
        cmdline[i++] =  arg_repair;
        cmdline[i++] = "-T";

        /*
         * Since util-linux v2.25 fsck uses /run/fsck/<diskname>.lock files.
         * The previous versions use flock for the device and conflict with
         * udevd, see https://bugs.freedesktop.org/show_bug.cgi?id=79576#c5
         */
        cmdline[i++] = "-l";

        if (!root_directory)
                cmdline[i++] = "-M";

        if (arg_force)
                cmdline[i++] = "-f";

        xsprintf(dash_c, "-C%i", progress_pipe[1]);
        cmdline[i++] = dash_c;

        cmdline[i++] = device;
        cmdline[i++] = NULL;

        pid = fork();
        if (pid < 0) {
                r = log_error_errno(errno, "fork(): %m");
                goto finish;
        } else if (pid == 0) {
                /* Child */
                progress_pipe[0] = safe_close(progress_pipe[0]);
                execv(cmdline[0], (char**) cmdline);
                _exit(8); /* Operational error */
        }

        progress_pipe[1] = safe_close(progress_pipe[1]);

        progress_rc = process_progress(progress_pipe[0], pid, st.st_rdev);
        progress_pipe[0] = -1;

        r = wait_for_terminate(pid, &status);
        if (r < 0) {
                log_error_errno(r, "waitid(): %m");
                goto finish;
        }

        if (status.si_code != CLD_EXITED || (status.si_status & ~1) || progress_rc != 0) {

                /* cancel will kill fsck (but process_progress returns 0) */
                if ((progress_rc != 0 && status.si_code == CLD_KILLED) || status.si_code == CLD_DUMPED)
                        log_error("fsck terminated by signal %s.", signal_to_string(status.si_status));
                else if (status.si_code == CLD_EXITED)
                        log_error("fsck failed with error code %i.", status.si_status);
                else if (progress_rc != 0)
                        log_error("fsck failed due to unknown reason.");

                r = -EINVAL;

                if (status.si_code == CLD_EXITED && (status.si_status & 2) && root_directory)
                        /* System should be rebooted. */
                        start_target(SPECIAL_REBOOT_TARGET);
                else if (status.si_code == CLD_EXITED && (status.si_status & 6))
                        /* Some other problem */
                        start_target(SPECIAL_EMERGENCY_TARGET);
                else {
                        r = 0;
                        if (progress_rc != 0)
                                log_warning("Ignoring error.");
                }

        } else
                r = 0;

        if (status.si_code == CLD_EXITED && (status.si_status & 1))
                touch("/run/systemd/quotacheck");

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
