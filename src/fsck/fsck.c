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
#include <sys/prctl.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "util.h"
#include "process-util.h"
#include "signal-util.h"
#include "special.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-common-errors.h"
#include "device-util.h"
#include "path-util.h"
#include "socket-util.h"

/* exit codes as defined in fsck(8) */
enum {
        FSCK_SUCCESS = 0,
        FSCK_ERROR_CORRECTED = 1,
        FSCK_SYSTEM_SHOULD_REBOOT = 2,
        FSCK_ERRORS_LEFT_UNCORRECTED = 4,
        FSCK_OPERATIONAL_ERROR = 8,
        FSCK_USAGE_OR_SYNTAX_ERROR = 16,
        FSCK_USER_CANCELLED = 32,
        FSCK_SHARED_LIB_ERROR = 128,
};

static bool arg_skip = false;
static bool arg_force = false;
static bool arg_show_progress = false;
static const char *arg_repair = "-a";

static void start_target(const char *target) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
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
                log_error("Failed to start unit: %s", bus_error_message(&error, r));
}

static int parse_proc_cmdline_item(const char *key, const char *value) {
        int r;

        assert(key);

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
                else {
                        r = parse_boolean(value);
                        if (r > 0)
                                arg_repair = "-y";
                        else if (r == 0)
                                arg_repair = "-n";
                        else
                                log_warning("Invalid fsck.repair= parameter '%s'. Ignoring.", value);
                }
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

        arg_show_progress = access("/run/systemd/show-status", F_OK) >= 0;
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
        int clear = 0, r;

        /* No progress pipe to process? Then we are a NOP. */
        if (fd < 0)
                return 0;

        f = fdopen(fd, "re");
        if (!f) {
                safe_close(fd);
                return -errno;
        }

        console = fopen("/dev/console", "we");
        if (!console)
                return -ENOMEM;

        for (;;) {
                int pass, m;
                unsigned long cur, max;
                _cleanup_free_ char *device = NULL;
                double p;
                usec_t t;

                if (fscanf(f, "%i %lu %lu %ms", &pass, &cur, &max, &device) != 4) {

                        if (ferror(f))
                                r = log_warning_errno(errno, "Failed to read from progress pipe: %m");
                        else if (feof(f))
                                r = 0;
                        else {
                                log_warning("Failed to parse progress pipe data");
                                r = -EBADMSG;
                        }
                        break;
                }

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

        return r;
}

static int fsck_progress_socket(void) {
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/fsck.progress",
        };

        int fd, r;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return log_warning_errno(errno, "socket(): %m");

        if (connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                r = log_full_errno(errno == ECONNREFUSED || errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                                   errno, "Failed to connect to progress socket %s, ignoring: %m", sa.un.sun_path);
                safe_close(fd);
                return r;
        }

        return fd;
}

int main(int argc, char *argv[]) {
        _cleanup_close_pair_ int progress_pipe[2] = { -1, -1 };
        _cleanup_device_unref_ sd_device *dev = NULL;
        const char *device, *type;
        bool root_directory;
        siginfo_t status;
        struct stat st;
        int r;
        pid_t pid;

        if (argc > 2) {
                log_error("This program expects one or no arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        r = parse_proc_cmdline(parse_proc_cmdline_item);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        test_files();

        if (!arg_force && arg_skip) {
                r = 0;
                goto finish;
        }

        if (argc > 1) {
                device = argv[1];

                if (stat(device, &st) < 0) {
                        r = log_error_errno(errno, "Failed to stat %s: %m", device);
                        goto finish;
                }

                if (!S_ISBLK(st.st_mode)) {
                        log_error("%s is not a block device.", device);
                        r = -EINVAL;
                        goto finish;
                }

                r = sd_device_new_from_devnum(&dev, 'b', st.st_rdev);
                if (r < 0) {
                        log_error_errno(r, "Failed to detect device %s: %m", device);
                        goto finish;
                }

                root_directory = false;
        } else {
                struct timespec times[2];

                /* Find root device */

                if (stat("/", &st) < 0) {
                        r = log_error_errno(errno, "Failed to stat() the root directory: %m");
                        goto finish;
                }

                /* Virtual root devices don't need an fsck */
                if (major(st.st_dev) == 0) {
                        log_debug("Root directory is virtual or btrfs, skipping check.");
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
                        log_warning_errno(r, "Couldn't detect if fsck.%s may be used for %s: %m", type, device);
        }

        if (arg_show_progress) {
                if (pipe(progress_pipe) < 0) {
                        r = log_error_errno(errno, "pipe(): %m");
                        goto finish;
                }
        }

        pid = fork();
        if (pid < 0) {
                r = log_error_errno(errno, "fork(): %m");
                goto finish;
        }
        if (pid == 0) {
                char dash_c[sizeof("-C")-1 + DECIMAL_STR_MAX(int) + 1];
                int progress_socket = -1;
                const char *cmdline[9];
                int i = 0;

                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                /* Close the reading side of the progress pipe */
                progress_pipe[0] = safe_close(progress_pipe[0]);

                /* Try to connect to a progress management daemon, if there is one */
                progress_socket = fsck_progress_socket();
                if (progress_socket >= 0) {
                        /* If this worked we close the progress pipe early, and just use the socket */
                        progress_pipe[1] = safe_close(progress_pipe[1]);
                        xsprintf(dash_c, "-C%i", progress_socket);
                } else if (progress_pipe[1] >= 0) {
                        /* Otherwise if we have the progress pipe to our own local handle, we use it */
                        xsprintf(dash_c, "-C%i", progress_pipe[1]);
                } else
                        dash_c[0] = 0;

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

                if (!isempty(dash_c))
                        cmdline[i++] = dash_c;

                cmdline[i++] = device;
                cmdline[i++] = NULL;

                execv(cmdline[0], (char**) cmdline);
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        progress_pipe[1] = safe_close(progress_pipe[1]);
        (void) process_progress(progress_pipe[0]);
        progress_pipe[0] = -1;

        r = wait_for_terminate(pid, &status);
        if (r < 0) {
                log_error_errno(r, "waitid(): %m");
                goto finish;
        }

        if (status.si_code != CLD_EXITED || (status.si_status & ~1)) {

                if (status.si_code == CLD_KILLED || status.si_code == CLD_DUMPED)
                        log_error("fsck terminated by signal %s.", signal_to_string(status.si_status));
                else if (status.si_code == CLD_EXITED)
                        log_error("fsck failed with error code %i.", status.si_status);
                else
                        log_error("fsck failed due to unknown reason.");

                r = -EINVAL;

                if (status.si_code == CLD_EXITED && (status.si_status & FSCK_SYSTEM_SHOULD_REBOOT) && root_directory)
                        /* System should be rebooted. */
                        start_target(SPECIAL_REBOOT_TARGET);
                else if (status.si_code == CLD_EXITED && (status.si_status & (FSCK_SYSTEM_SHOULD_REBOOT | FSCK_ERRORS_LEFT_UNCORRECTED)))
                        /* Some other problem */
                        start_target(SPECIAL_EMERGENCY_TARGET);
                else {
                        log_warning("Ignoring error.");
                        r = 0;
                }

        } else
                r = 0;

        if (status.si_code == CLD_EXITED && (status.si_status & FSCK_ERROR_CORRECTED))
                (void) touch("/run/systemd/quotacheck");

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
