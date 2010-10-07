/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 ProFUSION embedded systems

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "umount.h"
#include "util.h"

#define TIMEOUT_USEC    (5 * USEC_PER_SEC)
#define FINALIZE_ATTEMPTS 50
#define FINALIZE_CRITICAL_ATTEMPTS 10

static bool ignore_proc(pid_t pid) {
        if (pid == 1)
                return true;

        /* TODO: add more ignore rules here: device-mapper, etc */

        return false;
}

static bool is_kernel_thread(pid_t pid)
{
        char buf[PATH_MAX];
        FILE *f;
        char c;
        size_t count;

        snprintf(buf, sizeof(buf), "/proc/%lu/cmdline", (unsigned long)pid);
        f = fopen(buf, "re");
        if (!f)
                return true; /* not really, but has the desired effect */

        count = fread(&c, 1, 1, f);
        fclose(f);
        return count != 1;
}

static int killall(int sign) {
        DIR *dir;
        struct dirent *d;
        unsigned int processes = 0;

        if ((dir = opendir("/proc")) == NULL)
                return -errno;

        while ((d = readdir(dir))) {
                pid_t pid;

                if (parse_pid(d->d_name, &pid) < 0)
                        continue;

                if (is_kernel_thread(pid))
                        continue;

                if (ignore_proc(pid))
                        continue;

                if (kill(pid, sign) == 0)
                        processes++;
                else
                        log_warning("Could not kill %d: %m", pid);
        }

        closedir(dir);

        return processes;
}

static int send_signal(int sign) {
        sigset_t mask, oldmask;
        usec_t until;
        int processes;
        struct timespec ts;

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        if (sigprocmask(SIG_BLOCK, &mask, &oldmask) != 0)
                return -errno;

        if (kill(-1, SIGSTOP) < 0)
                log_warning("Failed kill(-1, SIGSTOP): %m");

        processes = killall(sign);

        if (kill(-1, SIGCONT) < 0)
                log_warning("Failed kill(-1, SIGCONT): %m");

        if (processes <= 0)
                goto finish;

        until = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;
        for (;;) {
                usec_t n = now(CLOCK_MONOTONIC);
                for (;;) {
                        pid_t pid = waitpid(-1, NULL, WNOHANG);
                        if (pid == 0)
                                break;
                        else if (pid < 0 && errno == ECHILD) {
                                processes = 0;
                                goto finish;
                        }

                        if (--processes == 0)
                                goto finish;
                }

                if (n >= until)
                        goto finish;

                timespec_store(&ts, until - n);
                if (sigtimedwait(&mask, NULL, &ts) != SIGCHLD)
                        log_warning("Failed: sigtimedwait did not return SIGCHLD: %m");
        }

finish:
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

        return processes;
}

static int rescue_send_signal(int sign) {
        sigset_t mask, oldmask;
        usec_t until;
        struct timespec ts;
        int r;

        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &mask, &oldmask) != 0)
                return -errno;

        if (kill(-1, SIGSTOP) < 0)
                log_warning("Failed kill(-1, SIGSTOP): %m");

        r = kill(-1, sign);
        if (r < 0)
                log_warning("Failed kill(-1, %d): %m", sign);

        if (kill(-1, SIGCONT) < 0)
                log_warning("Failed kill(-1, SIGCONT): %m");

        if (r < 0)
                goto finish;

        until = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;
        for (;;) {
                usec_t n = now(CLOCK_MONOTONIC);
                for (;;) {
                        pid_t pid = waitpid(-1, NULL, WNOHANG);
                        if (pid == 0)
                                break;
                        else if (pid < 0 && errno == ECHILD)
                                goto finish;
                }

                if (n >= until)
                        goto finish;

                timespec_store(&ts, until - n);
                if (sigtimedwait(&mask, NULL, &ts) != SIGCHLD)
                        log_warning("Failed: sigtimedwait did not return SIGCHLD: %m");
        }

finish:
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

        return r;
}


int main(int argc, char *argv[]) {
        int cmd, r, retries;
        bool need_umount = true, need_swapoff = true, need_loop_detach = true;

        log_parse_environment();
        log_set_target(LOG_TARGET_KMSG); /* syslog will die if not gone yet */
        log_open();

        if (getpid() != 1) {
                log_error("Not executed by init (pid-1).");
                r = -EPERM;
                goto error;
        }

        if (argc != 2) {
                log_error("Invalid number of arguments.");
                r = -EINVAL;
                goto error;
        }

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

        /* lock us into memory */
        if (mlockall(MCL_CURRENT|MCL_FUTURE) != 0)
                log_warning("Cannot lock process memory: %m");

        log_info("Sending SIGTERM to processes");
        r = send_signal(SIGTERM);
        if (r < 0)
                log_warning("Cannot send SIGTERM to all process: %s", strerror(r));

        log_info("Sending SIGKILL to processes");
        r = send_signal(SIGKILL);
        if (r < 0)
                log_warning("Cannot send SIGKILL to all process: %s", strerror(r));


        /* preventing that we won't block umounts */
        if (chdir("/") != 0)
                log_warning("Cannot chdir(\"/\"): %m. Unmounts likely to fail.");

        /* umount all mountpoints, swaps, and loopback devices */
        retries = FINALIZE_ATTEMPTS;
        while (need_umount || need_swapoff || need_loop_detach) {
                if (need_umount) {
                        log_info("Unmounting filesystems.");
                        r = umount_all();
                        if (r == 0)
                                need_umount = false;
                        else if (r > 0)
                                log_warning("Not all filesystems unmounted, %d left.", r);
                        else
                                log_error("Error unmounting filesystems: %s", strerror(-r));
                }

                if (need_swapoff) {
                        log_info("Disabling swaps.");
                        r = swapoff_all();
                        if (r == 0)
                                need_swapoff = false;
                        else if (r > 0)
                                log_warning("Not all swaps are off, %d left.", r);
                        else
                                log_error("Error turning off swaps: %s", strerror(-r));
                }

                if (need_loop_detach) {
                        log_info("Detaching loop devices.");
                        r = loopback_detach_all();
                        if (r == 0)
                                need_loop_detach = false;
                        else if (r > 0)
                                log_warning("Not all loop devices detached, %d left.", r);
                        else
                                log_error("Error detaching loop devices: %s", strerror(-r));

                }

                if (need_umount || need_swapoff || need_loop_detach) {
                        retries--;

                        if (retries <= FINALIZE_CRITICAL_ATTEMPTS) {
                                log_warning("Approaching critical level to finalize filesystem and devices, try to kill all processes.");
                                rescue_send_signal(SIGTERM);
                                rescue_send_signal(SIGKILL);
                        }

                        if (retries > 0)
                                log_info("Action still required, %d tries left", retries);
                        else {
                                log_error("Tried enough but still action required need_umount=%d, need_swapoff=%d, need_loop_detach=%d", need_umount, need_swapoff, need_loop_detach);
                                r = -EBUSY;
                                goto error;
                        }
                }
        }

        sync();

        if (cmd == LINUX_REBOOT_CMD_KEXEC) {
                /* we cheat and exec kexec to avoid doing all its work */
                pid_t pid = fork();
                if (pid < 0) {
                        log_error("Could not fork: %m. Falling back to reboot.");
                        cmd = RB_AUTOBOOT;
                } else if (pid > 0) {
                        waitpid(pid, NULL, 0);
                        log_warning("Failed %s -e -x -f. Falling back to reboot", KEXEC_BINARY_PATH);
                        cmd = RB_AUTOBOOT;
                } else {
                        const char *args[5] = {KEXEC_BINARY_PATH, "-e", "-f", "-x", NULL};
                        execv(args[0], (char * const *) args);
                        return EXIT_FAILURE;
                }
        }

        reboot(cmd);
        r = errno;

  error:
        sync();
        if (r < 0)
                r = -r;
        log_error("Critical error while doing system shutdown: %s", strerror(r));
        freeze();
        return EXIT_FAILURE;
}
