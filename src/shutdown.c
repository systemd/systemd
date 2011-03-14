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

#define TIMEOUT_USEC (5 * USEC_PER_SEC)
#define FINALIZE_ATTEMPTS 50

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
        unsigned int n_processes = 0;

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
                        n_processes++;
                else
                        log_warning("Could not kill %d: %m", pid);
        }

        closedir(dir);

        return n_processes;
}

static void wait_for_children(int n_processes, sigset_t *mask) {
        usec_t until;

        assert(mask);

        until = now(CLOCK_MONOTONIC) + TIMEOUT_USEC;
        for (;;) {
                struct timespec ts;
                int k;
                usec_t n;

                for (;;) {
                        pid_t pid = waitpid(-1, NULL, WNOHANG);

                        if (pid == 0)
                                break;

                        if (pid < 0 && errno == ECHILD)
                                return;

                        if (n_processes > 0)
                                if (--n_processes == 0)
                                        return;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= until)
                        return;

                timespec_store(&ts, until - n);

                if ((k = sigtimedwait(mask, NULL, &ts)) != SIGCHLD) {

                        if (k < 0 && errno != EAGAIN) {
                                log_error("sigtimedwait() failed: %m");
                                return;
                        }

                        if (k >= 0)
                                log_warning("sigtimedwait() returned unexpected signal.");
                }
        }
}

static void send_signal(int sign) {
        sigset_t mask, oldmask;
        int n_processes;

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        if (kill(-1, SIGSTOP) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGSTOP) failed: %m");

        n_processes = killall(sign);

        if (kill(-1, SIGCONT) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGCONT) failed: %m");

        if (n_processes <= 0)
                goto finish;

        wait_for_children(n_processes, &mask);

finish:
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

static void ultimate_send_signal(int sign) {
        sigset_t mask, oldmask;
        int r;

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigaddset(&mask, SIGCHLD) == 0);
        assert_se(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0);

        if (kill(-1, SIGSTOP) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGSTOP) failed: %m");

        r = kill(-1, sign);
        if (r < 0 && errno != ESRCH)
                log_warning("kill(-1, %s) failed: %m", signal_to_string(sign));

        if (kill(-1, SIGCONT) < 0 && errno != ESRCH)
                log_warning("kill(-1, SIGCONT) failed: %m");

        if (r < 0)
                goto finish;

        wait_for_children(0, &mask);

finish:
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

int main(int argc, char *argv[]) {
        int cmd, r;
        unsigned retries;
        bool need_umount = true, need_swapoff = true, need_loop_detach = true, need_dm_detach = true;
        bool killed_everbody = false, in_container;

        log_parse_environment();
        log_set_target(LOG_TARGET_CONSOLE); /* syslog will die if not gone yet */
        log_open();

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

        /* lock us into memory */
        if (mlockall(MCL_CURRENT|MCL_FUTURE) != 0)
                log_warning("Cannot lock process memory: %m");

        log_info("Sending SIGTERM to remaining processes...");
        send_signal(SIGTERM);

        log_info("Sending SIGKILL to remaining processes...");
        send_signal(SIGKILL);

        if (in_container)
                need_swapoff = false;

        /* Unmount all mountpoints, swaps, and loopback devices */
        for (retries = 0; retries < FINALIZE_ATTEMPTS; retries++) {
                bool changed = false;

                if (need_umount) {
                        log_info("Unmounting file systems.");
                        r = umount_all(&changed);
                        if (r == 0)
                                need_umount = false;
                        else if (r > 0)
                                log_info("Not all file systems unmounted, %d left.", r);
                        else
                                log_error("Failed to unmount file systems: %s", strerror(-r));
                }

                if (need_swapoff) {
                        log_info("Disabling swaps.");
                        r = swapoff_all(&changed);
                        if (r == 0)
                                need_swapoff = false;
                        else if (r > 0)
                                log_info("Not all swaps are turned off, %d left.", r);
                        else
                                log_error("Failed to turn off swaps: %s", strerror(-r));
                }

                if (need_loop_detach) {
                        log_info("Detaching loop devices.");
                        r = loopback_detach_all(&changed);
                        if (r == 0)
                                need_loop_detach = false;
                        else if (r > 0)
                                log_info("Not all loop devices detached, %d left.", r);
                        else
                                log_error("Failed to detach loop devices: %s", strerror(-r));
                }

                if (need_dm_detach) {
                        log_info("Detaching DM devices.");
                        r = dm_detach_all(&changed);
                        if (r == 0)
                                need_dm_detach = false;
                        else if (r > 0)
                                log_warning("Not all DM devices detached, %d left.", r);
                        else
                                log_error("Failed to detach DM devices: %s", strerror(-r));
                }

                if (!need_umount && !need_swapoff && !need_loop_detach && !need_dm_detach)
                        /* Yay, done */
                        break;

                /* If in this iteration we didn't manage to
                 * unmount/deactivate anything, we either kill more
                 * processes, or simply give up */
                if (!changed) {

                        if (killed_everbody) {
                                /* Hmm, we already killed everybody,
                                 * let's just give up */
                                log_error("Cannot finalize remaining file systems and devices, giving up.");
                                break;
                        }

                        log_warning("Cannot finalize remaining file systems and devices, trying to kill remaining processes.");
                        ultimate_send_signal(SIGTERM);
                        ultimate_send_signal(SIGKILL);
                        killed_everbody = true;
                }

                log_debug("Couldn't finalize remaining file systems and devices after %u retries, trying again.", retries+1);
        }

        if (retries >= FINALIZE_ATTEMPTS)
                log_error("Too many iterations, giving up.");

        execute_directory(SYSTEM_SHUTDOWN_PATH, NULL, NULL);

        /* If we are in a container, just exit, this will kill our
         * container for good. */
        if (in_container)
                exit(0);

        sync();

        if (cmd == LINUX_REBOOT_CMD_KEXEC) {
                /* We cheat and exec kexec to avoid doing all its work */
                pid_t pid = fork();

                if (pid < 0)
                        log_error("Could not fork: %m. Falling back to normal reboot.");
                else if (pid > 0) {
                        wait_for_terminate_and_warn("kexec", pid);
                        log_warning("kexec failed. Falling back to normal reboot.");
                } else {
                        /* Child */
                        const char *args[3] = { "/sbin/kexec", "-e", NULL };
                        execv(args[0], (char * const *) args);
                        return EXIT_FAILURE;
                }

                cmd = RB_AUTOBOOT;
        }

        reboot(cmd);
        log_error("Failed to invoke reboot(): %m");
        r = -errno;

  error:
        log_error("Critical error while doing system shutdown: %s", strerror(-r));

        freeze();
        return EXIT_FAILURE;
}
