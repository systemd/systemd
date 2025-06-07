/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2014 Holger Hans Peter Freyther
***/

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "device-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fsck-util.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "socket-util.h"
#include "special.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"

static bool arg_skip = false;
static bool arg_force = false;
static bool arg_show_progress = false;
static const char *arg_repair = "-a";

static void start_target(const char *target, const char *mode) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(target);

        r = bus_connect_system_systemd(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to get D-Bus connection: %m");
                return;
        }

        log_info("Requesting %s/start/%s", target, mode);

        /* Start this unit only if we can replace basic.target with it */
        r = bus_call_method(bus, bus_systemd_mgr, "StartUnitReplace", &error, NULL, "sss", SPECIAL_BASIC_TARGET, target, mode);

        /* Don't print a warning if we aren't called during startup */
        if (r < 0 && !sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_JOB))
                log_error("Failed to start unit: %s", bus_error_message(&error, r));
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (streq(key, "fsck.mode")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (streq(value, "auto"))
                        arg_force = arg_skip = false;
                else if (streq(value, "force"))
                        arg_force = true;
                else if (streq(value, "skip"))
                        arg_skip = true;
                else
                        log_warning("Invalid fsck.mode= parameter '%s'. Ignoring.", value);

        } else if (streq(key, "fsck.repair")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

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

        else if (streq(key, "fastboot") && !value)
                arg_skip = true;

        else if (streq(key, "forcefsck") && !value)
                arg_force = true;

        return 0;
}

static void test_files(void) {

#if HAVE_SYSV_COMPAT
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

static int process_progress(int fd, FILE* console) {
        _cleanup_fclose_ FILE *f = NULL;
        usec_t last = 0;
        bool locked = false;
        int clear = 0, r;

        /* No progress pipe to process? Then we are a NOP. */
        if (fd < 0)
                return 0;

        f = fdopen(fd, "r");
        if (!f) {
                safe_close(fd);
                return log_debug_errno(errno, "Failed to use pipe: %m");
        }

        for (;;) {
                int pass;
                unsigned long cur, max;
                _cleanup_free_ char *device = NULL;
                double p;
                usec_t t;

                if (fscanf(f, "%i %lu %lu %ms", &pass, &cur, &max, &device) != 4) {

                        if (ferror(f))
                                r = log_warning_errno(errno, "Failed to read from progress pipe: %m");
                        else if (feof(f))
                                r = 0;
                        else
                                r = log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse progress pipe data.");

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
                r = fprintf(console, "\r%s: fsck %3.1f%% complete...\r", device, p);
                if (r < 0)
                        return -EIO; /* No point in continuing if something happened to our output stream */

                fflush(console);
                clear = MAX(clear, r);
        }

        if (clear > 0) {
                fputc('\r', console);
                for (int j = 0; j < clear; j++)
                        fputc(' ', console);
                fputc('\r', console);
                fflush(console);
        }

        return r;
}

static int fsck_progress_socket(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return log_warning_errno(errno, "socket(): %m");

        r = connect_unix_path(fd, AT_FDCWD, "/run/systemd/fsck.progress");
        if (r < 0)
                return log_full_errno(IN_SET(r, -ECONNREFUSED, -ENOENT) ? LOG_DEBUG : LOG_WARNING,
                                      r, "Failed to connect to progress socket, ignoring: %m");

        return TAKE_FD(fd);
}

static int run(int argc, char *argv[]) {
        _cleanup_close_pair_ int progress_pipe[2] = EBADF_PAIR;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *dpath = NULL;
        _cleanup_fclose_ FILE *console = NULL;
        const char *device, *type;
        bool root_directory;
        struct stat st;
        int r, exit_status;
        pid_t pid;

        log_setup();

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program expects one or no arguments.");

        umask(0022);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        test_files();

        if (!arg_force && arg_skip)
                return 0;

        if (argc > 1) {
                dpath = strdup(argv[1]);
                if (!dpath)
                        return log_oom();

                device = dpath;

                if (stat(device, &st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", device);

                if (!S_ISBLK(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "%s is not a block device.",
                                               device);

                r = sd_device_new_from_stat_rdev(&dev, &st);
                if (r < 0)
                        return log_error_errno(r, "Failed to detect device %s: %m", device);

                root_directory = false;
        } else {
                struct timespec times[2];

                /* Find root device */

                if (stat("/", &st) < 0)
                        return log_error_errno(errno, "Failed to stat() the root directory: %m");

                /* Virtual root devices don't need an fsck */
                if (major(st.st_dev) == 0) {
                        log_debug("Root directory is virtual or btrfs, skipping check.");
                        return 0;
                }

                /* check if we are already writable */
                times[0] = st.st_atim;
                times[1] = st.st_mtim;

                if (utimensat(AT_FDCWD, "/", times, 0) == 0) {
                        log_info("Root directory is writable, skipping check.");
                        return 0;
                }

                r = sd_device_new_from_devnum(&dev, 'b', st.st_dev);
                if (r < 0)
                        return log_error_errno(r, "Failed to detect root device: %m");

                r = sd_device_get_devname(dev, &device);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to detect device node of root directory: %m");

                root_directory = true;
        }

        if (sd_device_get_property_value(dev, "ID_FS_TYPE", &type) >= 0) {
                r = fsck_exists_for_fstype(type);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Couldn't detect if fsck.%s may be used, proceeding: %m", type);
                else if (r == 0) {
                        log_device_info(dev, "fsck.%s doesn't exist, not checking file system.", type);
                        return 0;
                }
        } else {
                r = fsck_exists();
                if (r < 0)
                        log_device_warning_errno(dev, r, "Couldn't detect if the fsck command may be used, proceeding: %m");
                else if (r == 0) {
                        log_device_info(dev, "The fsck command does not exist, not checking file system.");
                        return 0;
                }
        }

        console = fopen("/dev/console", "we");
        if (console &&
            arg_show_progress &&
            pipe(progress_pipe) < 0)
                return log_error_errno(errno, "pipe(): %m");

        r = safe_fork("(fsck)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                char dash_c[STRLEN("-C") + DECIMAL_STR_MAX(int) + 1];
                int progress_socket = -1;
                const char *cmdline[9];
                int i = 0;

                /* Child */

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

                cmdline[i++] = "fsck";
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

                execvp(cmdline[0], (char**) cmdline);
                _exit(FSCK_OPERATIONAL_ERROR);
        }

        if (console) {
                progress_pipe[1] = safe_close(progress_pipe[1]);
                (void) process_progress(TAKE_FD(progress_pipe[0]), console);
        }

        exit_status = wait_for_terminate_and_check("fsck", pid, WAIT_LOG_ABNORMAL);
        if (exit_status < 0)
                return exit_status;
        if ((exit_status & ~FSCK_ERROR_CORRECTED) != FSCK_SUCCESS) {
                log_error("fsck failed with exit status %i.", exit_status);

                if ((exit_status & FSCK_SYSTEM_SHOULD_REBOOT) && root_directory) {
                        /* System should be rebooted. */
                        start_target(SPECIAL_REBOOT_TARGET, "replace-irreversibly");
                        return -EINVAL;
                } else if (!(exit_status & (FSCK_SYSTEM_SHOULD_REBOOT | FSCK_ERRORS_LEFT_UNCORRECTED)))
                        log_warning("Ignoring error.");
        }

        if (exit_status & FSCK_ERROR_CORRECTED)
                (void) touch("/run/systemd/quotacheck");

        return !!(exit_status & (FSCK_SYSTEM_SHOULD_REBOOT | FSCK_ERRORS_LEFT_UNCORRECTED));
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
