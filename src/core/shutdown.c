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
#include <sys/types.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "missing.h"
#include "log.h"
#include "fileio.h"
#include "umount.h"
#include "util.h"
#include "mkdir.h"
#include "virt.h"
#include "watchdog.h"
#include "killall.h"

#define FINALIZE_ATTEMPTS 50

static int prepare_new_root(void) {
        static const char dirs[] =
                "/run/initramfs/oldroot\0"
                "/run/initramfs/proc\0"
                "/run/initramfs/sys\0"
                "/run/initramfs/dev\0"
                "/run/initramfs/run\0";

        const char *dir;

        if (mount("/run/initramfs", "/run/initramfs", NULL, MS_BIND, NULL) < 0) {
                log_error("Failed to mount bind /run/initramfs on /run/initramfs: %m");
                return -errno;
        }

        if (mount(NULL, "/run/initramfs", NULL, MS_PRIVATE, NULL) < 0) {
                log_error("Failed to make /run/initramfs private mount: %m");
                return -errno;
        }

        NULSTR_FOREACH(dir, dirs)
                if (mkdir_p_label(dir, 0755) < 0 && errno != EEXIST) {
                        log_error("Failed to mkdir %s: %m", dir);
                        return -errno;
                }

        if (mount("/sys", "/run/initramfs/sys", NULL, MS_BIND, NULL) < 0) {
                log_error("Failed to mount bind /sys on /run/initramfs/sys: %m");
                return -errno;
        }

        if (mount("/proc", "/run/initramfs/proc", NULL, MS_BIND, NULL) < 0) {
                log_error("Failed to mount bind /proc on /run/initramfs/proc: %m");
                return -errno;
        }

        if (mount("/dev", "/run/initramfs/dev", NULL, MS_BIND, NULL) < 0) {
                log_error("Failed to mount bind /dev on /run/initramfs/dev: %m");
                return -errno;
        }

        if (mount("/run", "/run/initramfs/run", NULL, MS_BIND, NULL) < 0) {
                log_error("Failed to mount bind /run on /run/initramfs/run: %m");
                return -errno;
        }

        return 0;
}

static int pivot_to_new_root(void) {

        if (chdir("/run/initramfs") < 0) {
                log_error("Failed to change directory to /run/initramfs: %m");
                return -errno;
        }

        /* Work-around for a kernel bug: for some reason the kernel
         * refuses switching root if any file systems are mounted
         * MS_SHARED. Hence remount them MS_PRIVATE here as a
         * work-around.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=847418 */
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
                log_warning("Failed to make \"/\" private mount: %m");

        if (pivot_root(".", "oldroot") < 0) {
                log_error("pivot failed: %m");
                /* only chroot if pivot root succeeded */
                return -errno;
        }

        chroot(".");

        setsid();
        make_console_stdio();

        log_info("Successfully changed into root pivot.");

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *line = NULL;
        int cmd, r;
        unsigned retries;
        bool need_umount = true, need_swapoff = true, need_loop_detach = true, need_dm_detach = true;
        bool in_container, use_watchdog = false;
        char *arguments[3];

        /* suppress shutdown status output if 'quiet' is used  */
        r = read_one_line_file("/proc/cmdline", &line);
        if (r >= 0) {
                char *w, *state;
                size_t l;

                FOREACH_WORD_QUOTED(w, l, line, state) {
                        if (l == 5 && memcmp(w, "quiet", 5) == 0) {
                                log_set_max_level(LOG_WARNING);
                                break;
                        }
                }
        }

        log_parse_environment();
        log_set_target(LOG_TARGET_CONSOLE); /* syslog will die if not gone yet */
        log_open();

        umask(0022);

        if (getpid() != 1) {
                log_error("Not executed by init (pid 1).");
                r = -EPERM;
                goto error;
        }

        if (argc != 2) {
                log_error("Invalid number of arguments.");
                r = -EINVAL;
                goto error;
        }

        in_container = detect_container(NULL) > 0;

        if (streq(argv[1], "reboot"))
                cmd = RB_AUTOBOOT;
        else if (streq(argv[1], "poweroff"))
                cmd = RB_POWER_OFF;
        else if (streq(argv[1], "halt"))
                cmd = RB_HALT_SYSTEM;
        else if (streq(argv[1], "kexec"))
                cmd = LINUX_REBOOT_CMD_KEXEC;
        else {
                log_error("Unknown action '%s'.", argv[1]);
                r = -EINVAL;
                goto error;
        }

        use_watchdog = !!getenv("WATCHDOG_USEC");

        /* lock us into memory */
        mlockall(MCL_CURRENT|MCL_FUTURE);

        log_info("Sending SIGTERM to remaining processes...");
        broadcast_signal(SIGTERM, true);

        log_info("Sending SIGKILL to remaining processes...");
        broadcast_signal(SIGKILL, true);

        if (in_container) {
                need_swapoff = false;
                need_dm_detach = false;
                need_loop_detach = false;
        }

        /* Unmount all mountpoints, swaps, and loopback devices */
        for (retries = 0; retries < FINALIZE_ATTEMPTS; retries++) {
                bool changed = false;

                if (use_watchdog)
                        watchdog_ping();

                if (need_umount) {
                        log_info("Unmounting file systems.");
                        r = umount_all(&changed);
                        if (r == 0) {
                                need_umount = false;
                                log_info("All filesystems unmounted.");
                        } else if (r > 0)
                                log_info("Not all file systems unmounted, %d left.", r);
                        else
                                log_error("Failed to unmount file systems: %s", strerror(-r));
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
                                log_error("Failed to deactivate swaps: %s", strerror(-r));
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
                                log_error("Failed to detach loop devices: %s", strerror(-r));
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
                                log_error("Failed to detach DM devices: %s", strerror(-r));
                }

                if (!need_umount && !need_swapoff && !need_loop_detach && !need_dm_detach) {
                        if (retries > 0)
                                log_info("All filesystems, swaps, loop devices, DM devices detached.");
                        /* Yay, done */
                        break;
                }

                /* If in this iteration we didn't manage to
                 * unmount/deactivate anything, we simply give up */
                if (!changed) {
                        log_error("Cannot finalize remaining file systems and devices, giving up.");
                        break;
                }

                log_debug("Couldn't finalize remaining file systems and devices after %u retries, trying again.", retries+1);
        }

        if (retries >= FINALIZE_ATTEMPTS)
                log_error("Too many iterations, giving up.");
        else
                log_info("Storage is finalized.");

        arguments[0] = NULL;
        arguments[1] = argv[1];
        arguments[2] = NULL;
        execute_directory(SYSTEM_SHUTDOWN_PATH, NULL, arguments);

        if (!in_container && !in_initrd() &&
            access("/run/initramfs/shutdown", X_OK) == 0) {

                if (prepare_new_root() >= 0 &&
                    pivot_to_new_root() >= 0) {

                        log_info("Returning to initrd...");

                        execv("/shutdown", argv);
                        log_error("Failed to execute shutdown binary: %m");
                }
        }

        /* The kernel will automaticall flush ATA disks and suchlike
         * on reboot(), but the file systems need to be synce'd
         * explicitly in advance. So let's do this here, but not
         * needlessly slow down containers. */
        if (!in_container)
                sync();

        if (cmd == LINUX_REBOOT_CMD_KEXEC) {

                if (!in_container) {
                        /* We cheat and exec kexec to avoid doing all its work */
                        pid_t pid = fork();

                        if (pid < 0)
                                log_error("Could not fork: %m. Falling back to normal reboot.");
                        else if (pid > 0) {
                                wait_for_terminate_and_warn("kexec", pid);
                                log_warning("kexec failed. Falling back to normal reboot.");
                        } else {
                                /* Child */
                                const char *args[3] = { KEXEC, "-e", NULL };
                                execv(args[0], (char * const *) args);
                                return EXIT_FAILURE;
                        }
                }

                cmd = RB_AUTOBOOT;
        }

        reboot(cmd);

        if (errno == EPERM && in_container) {
                /* If we are in a container, and we lacked
                 * CAP_SYS_BOOT just exit, this will kill our
                 * container for good. */
                log_error("Exiting container.");
                exit(0);
        }

        log_error("Failed to invoke reboot(): %m");
        r = -errno;

  error:
        log_error("Critical error while doing system shutdown: %s", strerror(-r));

        freeze();
        return EXIT_FAILURE;
}
