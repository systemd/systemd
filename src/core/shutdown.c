/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

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

#include <sys/mman.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>

#include "missing.h"
#include "log.h"
#include "fileio.h"
#include "umount.h"
#include "util.h"
#include "virt.h"
#include "watchdog.h"
#include "killall.h"
#include "cgroup-util.h"
#include "def.h"
#include "switch-root.h"
#include "process-util.h"
#include "terminal-util.h"

#define FINALIZE_ATTEMPTS 50

static char* arg_verb;

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
        };

        static const struct option options[] = {
                { "log-level",     required_argument, NULL, ARG_LOG_LEVEL    },
                { "log-target",    required_argument, NULL, ARG_LOG_TARGET   },
                { "log-color",     optional_argument, NULL, ARG_LOG_COLOR    },
                { "log-location",  optional_argument, NULL, ARG_LOG_LOCATION },
                {}
        };

        int c, r;

        assert(argc >= 1);
        assert(argv);

        /* "-" prevents getopt from permuting argv[] and moving the verb away
         * from argv[1]. Our interface to initrd promises it'll be there. */
        while ((c = getopt_long(argc, argv, "-", options, NULL)) >= 0)
                switch (c) {

                case ARG_LOG_LEVEL:
                        r = log_set_max_level_from_string(optarg);
                        if (r < 0)
                                log_error("Failed to parse log level %s, ignoring.", optarg);

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0)
                                log_error("Failed to parse log target %s, ignoring", optarg);

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0)
                                        log_error("Failed to parse log color setting %s, ignoring", optarg);
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0)
                                        log_error("Failed to parse log location setting %s, ignoring", optarg);
                        } else
                                log_show_location(true);

                        break;

                case '\001':
                        if (!arg_verb)
                                arg_verb = optarg;
                        else
                                log_error("Excess arguments, ignoring");
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        if (!arg_verb) {
                log_error("Verb argument missing.");
                return -EINVAL;
        }

        return 0;
}

static int switch_root_initramfs(void) {
        if (mount("/run/initramfs", "/run/initramfs", NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to mount bind /run/initramfs on /run/initramfs: %m");

        if (mount(NULL, "/run/initramfs", NULL, MS_PRIVATE, NULL) < 0)
                return log_error_errno(errno, "Failed to make /run/initramfs private mount: %m");

        /* switch_root with MS_BIND, because there might still be processes lurking around, which have open file descriptors.
         * /run/initramfs/shutdown will take care of these.
         * Also do not detach the old root, because /run/initramfs/shutdown needs to access it.
         */
        return switch_root("/run/initramfs", "/oldroot", false, MS_BIND);
}


int main(int argc, char *argv[]) {
        bool need_umount, need_swapoff, need_loop_detach, need_dm_detach;
        bool in_container, use_watchdog = false;
        _cleanup_free_ char *cgroup = NULL;
        char *arguments[3];
        unsigned retries;
        int cmd, r;
        static const char* const dirs[] = {SYSTEM_SHUTDOWN_PATH, NULL};

        log_parse_environment();
        r = parse_argv(argc, argv);
        if (r < 0)
                goto error;

        /* journald will die if not gone yet. The log target defaults
         * to console, but may have been changed by command line options. */

        log_close_console(); /* force reopen of /dev/console */
        log_open();

        umask(0022);

        if (getpid() != 1) {
                log_error("Not executed by init (PID 1).");
                r = -EPERM;
                goto error;
        }

        if (streq(arg_verb, "reboot"))
                cmd = RB_AUTOBOOT;
        else if (streq(arg_verb, "poweroff"))
                cmd = RB_POWER_OFF;
        else if (streq(arg_verb, "halt"))
                cmd = RB_HALT_SYSTEM;
        else if (streq(arg_verb, "kexec"))
                cmd = LINUX_REBOOT_CMD_KEXEC;
        else {
                r = -EINVAL;
                log_error("Unknown action '%s'.", arg_verb);
                goto error;
        }

        cg_get_root_path(&cgroup);

        use_watchdog = !!getenv("WATCHDOG_USEC");

        /* lock us into memory */
        mlockall(MCL_CURRENT|MCL_FUTURE);

        log_info("Sending SIGTERM to remaining processes...");
        broadcast_signal(SIGTERM, true, true);

        log_info("Sending SIGKILL to remaining processes...");
        broadcast_signal(SIGKILL, true, false);

        in_container = detect_container(NULL) > 0;

        need_umount = !in_container;
        need_swapoff = !in_container;
        need_loop_detach = !in_container;
        need_dm_detach = !in_container;

        /* Unmount all mountpoints, swaps, and loopback devices */
        for (retries = 0; retries < FINALIZE_ATTEMPTS; retries++) {
                bool changed = false;

                if (use_watchdog)
                        watchdog_ping();

                /* Let's trim the cgroup tree on each iteration so
                   that we leave an empty cgroup tree around, so that
                   container managers get a nice notify event when we
                   are down */
                if (cgroup)
                        cg_trim(SYSTEMD_CGROUP_CONTROLLER, cgroup, false);

                if (need_umount) {
                        log_info("Unmounting file systems.");
                        r = umount_all(&changed);
                        if (r == 0) {
                                need_umount = false;
                                log_info("All filesystems unmounted.");
                        } else if (r > 0)
                                log_info("Not all file systems unmounted, %d left.", r);
                        else
                                log_error_errno(r, "Failed to unmount file systems: %m");
                }

                if (need_swapoff) {
                        log_info("Deactivating swaps.");
                        r = swapoff_all(&changed);
                        if (r == 0) {
                                need_swapoff = false;
                                log_info("All swaps deactivated.");
                        } else if (r > 0)
                                log_info("Not all swaps deactivated, %d left.", r);
                        else
                                log_error_errno(r, "Failed to deactivate swaps: %m");
                }

                if (need_loop_detach) {
                        log_info("Detaching loop devices.");
                        r = loopback_detach_all(&changed);
                        if (r == 0) {
                                need_loop_detach = false;
                                log_info("All loop devices detached.");
                        } else if (r > 0)
                                log_info("Not all loop devices detached, %d left.", r);
                        else
                                log_error_errno(r, "Failed to detach loop devices: %m");
                }

                if (need_dm_detach) {
                        log_info("Detaching DM devices.");
                        r = dm_detach_all(&changed);
                        if (r == 0) {
                                need_dm_detach = false;
                                log_info("All DM devices detached.");
                        } else if (r > 0)
                                log_info("Not all DM devices detached, %d left.", r);
                        else
                                log_error_errno(r, "Failed to detach DM devices: %m");
                }

                if (!need_umount && !need_swapoff && !need_loop_detach && !need_dm_detach) {
                        if (retries > 0)
                                log_info("All filesystems, swaps, loop devices, DM devices detached.");
                        /* Yay, done */
                        goto initrd_jump;
                }

                /* If in this iteration we didn't manage to
                 * unmount/deactivate anything, we simply give up */
                if (!changed) {
                        log_info("Cannot finalize remaining%s%s%s%s continuing.",
                                 need_umount ? " file systems," : "",
                                 need_swapoff ? " swap devices," : "",
                                 need_loop_detach ? " loop devices," : "",
                                 need_dm_detach ? " DM devices," : "");
                        goto initrd_jump;
                }

                log_debug("After %u retries, couldn't finalize remaining %s%s%s%s trying again.",
                          retries + 1,
                          need_umount ? " file systems," : "",
                          need_swapoff ? " swap devices," : "",
                          need_loop_detach ? " loop devices," : "",
                          need_dm_detach ? " DM devices," : "");
        }

        log_error("Too many iterations, giving up.");

 initrd_jump:

        arguments[0] = NULL;
        arguments[1] = arg_verb;
        arguments[2] = NULL;
        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, arguments);

        if (!in_container && !in_initrd() &&
            access("/run/initramfs/shutdown", X_OK) == 0) {
                r = switch_root_initramfs();
                if (r >= 0) {
                        argv[0] = (char*) "/shutdown";

                        setsid();
                        make_console_stdio();

                        log_info("Successfully changed into root pivot.\n"
                                 "Returning to initrd...");

                        execv("/shutdown", argv);
                        log_error_errno(errno, "Failed to execute shutdown binary: %m");
                } else
                        log_error_errno(r, "Failed to switch root to \"/run/initramfs\": %m");

        }

        if (need_umount || need_swapoff || need_loop_detach || need_dm_detach)
                log_error("Failed to finalize %s%s%s%s ignoring",
                          need_umount ? " file systems," : "",
                          need_swapoff ? " swap devices," : "",
                          need_loop_detach ? " loop devices," : "",
                          need_dm_detach ? " DM devices," : "");

        /* The kernel will automaticall flush ATA disks and suchlike
         * on reboot(), but the file systems need to be synce'd
         * explicitly in advance. So let's do this here, but not
         * needlessly slow down containers. */
        if (!in_container)
                sync();

        switch (cmd) {

        case LINUX_REBOOT_CMD_KEXEC:

                if (!in_container) {
                        /* We cheat and exec kexec to avoid doing all its work */
                        pid_t pid;

                        log_info("Rebooting with kexec.");

                        pid = fork();
                        if (pid < 0)
                                log_error_errno(errno, "Failed to fork: %m");
                        else if (pid == 0) {

                                const char * const args[] = {
                                        KEXEC, "-e", NULL
                                };

                                /* Child */

                                execv(args[0], (char * const *) args);
                                _exit(EXIT_FAILURE);
                        } else
                                wait_for_terminate_and_warn("kexec", pid, true);
                }

                cmd = RB_AUTOBOOT;
                /* Fall through */

        case RB_AUTOBOOT:

                if (!in_container) {
                        _cleanup_free_ char *param = NULL;

                        if (read_one_line_file(REBOOT_PARAM_FILE, &param) >= 0) {
                                log_info("Rebooting with argument '%s'.", param);
                                syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART2, param);
                        }
                }

                log_info("Rebooting.");
                break;

        case RB_POWER_OFF:
                log_info("Powering off.");
                break;

        case RB_HALT_SYSTEM:
                log_info("Halting system.");
                break;

        default:
                assert_not_reached("Unknown magic");
        }

        reboot(cmd);
        if (errno == EPERM && in_container) {
                /* If we are in a container, and we lacked
                 * CAP_SYS_BOOT just exit, this will kill our
                 * container for good. */
                log_info("Exiting container.");
                exit(0);
        }

        log_error_errno(errno, "Failed to invoke reboot(): %m");
        r = -errno;

  error:
        log_emergency_errno(r, "Critical error while doing system shutdown: %m");

        freeze();
}
