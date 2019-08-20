/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <errno.h>
#include <getopt.h>
#include <linux/reboot.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "async.h"
#include "cgroup-util.h"
#include "def.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "killall.h"
#include "log.h"
#include "missing.h"
#include "parse-util.h"
#include "process-util.h"
#include "reboot-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "switch-root.h"
#include "sysctl-util.h"
#include "terminal-util.h"
#include "umount.h"
#include "util.h"
#include "virt.h"
#include "watchdog.h"

#define SYNC_PROGRESS_ATTEMPTS 3
#define SYNC_TIMEOUT_USEC (10*USEC_PER_SEC)

static char* arg_verb;
static uint8_t arg_exit_code;
static usec_t arg_timeout = DEFAULT_TIMEOUT_USEC;

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_LOG_LEVEL = 0x100,
                ARG_LOG_TARGET,
                ARG_LOG_COLOR,
                ARG_LOG_LOCATION,
                ARG_EXIT_CODE,
                ARG_TIMEOUT,
        };

        static const struct option options[] = {
                { "log-level",     required_argument, NULL, ARG_LOG_LEVEL    },
                { "log-target",    required_argument, NULL, ARG_LOG_TARGET   },
                { "log-color",     optional_argument, NULL, ARG_LOG_COLOR    },
                { "log-location",  optional_argument, NULL, ARG_LOG_LOCATION },
                { "exit-code",     required_argument, NULL, ARG_EXIT_CODE    },
                { "timeout",       required_argument, NULL, ARG_TIMEOUT      },
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
                                log_error_errno(r, "Failed to parse log level %s, ignoring: %m", optarg);

                        break;

                case ARG_LOG_TARGET:
                        r = log_set_target_from_string(optarg);
                        if (r < 0)
                                log_error_errno(r, "Failed to parse log target %s, ignoring: %m", optarg);

                        break;

                case ARG_LOG_COLOR:

                        if (optarg) {
                                r = log_show_color_from_string(optarg);
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse log color setting %s, ignoring: %m", optarg);
                        } else
                                log_show_color(true);

                        break;

                case ARG_LOG_LOCATION:
                        if (optarg) {
                                r = log_show_location_from_string(optarg);
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse log location setting %s, ignoring: %m", optarg);
                        } else
                                log_show_location(true);

                        break;

                case ARG_EXIT_CODE:
                        r = safe_atou8(optarg, &arg_exit_code);
                        if (r < 0)
                                log_error_errno(r, "Failed to parse exit code %s, ignoring: %m", optarg);

                        break;

                case ARG_TIMEOUT:
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                log_error_errno(r, "Failed to parse shutdown timeout %s, ignoring: %m", optarg);

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

        if (!arg_verb)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb argument missing.");

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

/* Read the following fields from /proc/meminfo:
 *
 *  NFS_Unstable
 *  Writeback
 *  Dirty
 *
 * Return true if the sum of these fields is greater than the previous
 * value input. For all other issues, report the failure and indicate that
 * the sync is not making progress.
 */
static int sync_making_progress(unsigned long long *prev_dirty) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned long long val = 0;
        int ret;

        f = fopen("/proc/meminfo", "re");
        if (!f)
                return log_warning_errno(errno, "Failed to open /proc/meminfo: %m");

        for (;;) {
                _cleanup_free_ char *line = NULL;
                unsigned long long ull = 0;
                int q;

                q = read_line(f, LONG_LINE_MAX, &line);
                if (q < 0)
                        return log_warning_errno(q, "Failed to parse /proc/meminfo: %m");
                if (q == 0)
                        break;

                if (!first_word(line, "NFS_Unstable:") && !first_word(line, "Writeback:") && !first_word(line, "Dirty:"))
                        continue;

                errno = 0;
                if (sscanf(line, "%*s %llu %*s", &ull) != 1) {
                        if (errno != 0)
                                log_warning_errno(errno, "Failed to parse /proc/meminfo: %m");
                        else
                                log_warning("Failed to parse /proc/meminfo");

                        return false;
                }

                val += ull;
        }

        ret = *prev_dirty > val;
        *prev_dirty = val;
        return ret;
}

static void sync_with_progress(void) {
        unsigned long long dirty = ULLONG_MAX;
        unsigned checks;
        pid_t pid;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        /* Due to the possibility of the sync operation hanging, we fork a child process and monitor the progress. If
         * the timeout lapses, the assumption is that that particular sync stalled. */

        r = asynchronous_sync(&pid);
        if (r < 0) {
                log_error_errno(r, "Failed to fork sync(): %m");
                return;
        }

        log_info("Syncing filesystems and block devices.");

        /* Start monitoring the sync operation. If more than
         * SYNC_PROGRESS_ATTEMPTS lapse without progress being made,
         * we assume that the sync is stalled */
        for (checks = 0; checks < SYNC_PROGRESS_ATTEMPTS; checks++) {
                r = wait_for_terminate_with_timeout(pid, SYNC_TIMEOUT_USEC);
                if (r == 0)
                        /* Sync finished without error.
                         * (The sync itself does not return an error code) */
                        return;
                else if (r == -ETIMEDOUT) {
                        /* Reset the check counter if the "Dirty" value is
                         * decreasing */
                        if (sync_making_progress(&dirty) > 0)
                                checks = 0;
                } else {
                        log_error_errno(r, "Failed to sync filesystems and block devices: %m");
                        return;
                }
        }

        /* Only reached in the event of a timeout. We should issue a kill
         * to the stray process. */
        log_error("Syncing filesystems and block devices - timed out, issuing SIGKILL to PID "PID_FMT".", pid);
        (void) kill(pid, SIGKILL);
}

static int read_current_sysctl_printk_log_level(void) {
        _cleanup_free_ char *sysctl_printk_vals = NULL, *sysctl_printk_curr = NULL;
        int current_lvl;
        const char *p;
        int r;

        r = sysctl_read("kernel/printk", &sysctl_printk_vals);
        if (r < 0)
                return log_debug_errno(r, "Cannot read sysctl kernel.printk: %m");

        p = sysctl_printk_vals;
        r = extract_first_word(&p, &sysctl_printk_curr, NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to split out kernel printk priority: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Short read while reading kernel.printk sysctl");

        r = safe_atoi(sysctl_printk_curr, &current_lvl);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse kernel.printk sysctl: %s", sysctl_printk_vals);

        return current_lvl;
}

static void bump_sysctl_printk_log_level(int min_level) {
        int current_lvl, r;

        /* Set the logging level to be able to see messages with log level smaller or equal to min_level */

        current_lvl = read_current_sysctl_printk_log_level();
        if (current_lvl < 0 || current_lvl >= min_level + 1)
                return;

        r = sysctl_writef("kernel/printk", "%i", min_level + 1);
        if (r < 0)
                log_debug_errno(r, "Failed to bump kernel.printk to %i: %m", min_level + 1);
}

int main(int argc, char *argv[]) {
        bool need_umount, need_swapoff, need_loop_detach, need_dm_detach, in_container, use_watchdog = false, can_initrd;
        _cleanup_free_ char *cgroup = NULL;
        char *arguments[3], *watchdog_device;
        int cmd, r, umount_log_level = LOG_INFO;
        static const char* const dirs[] = {SYSTEM_SHUTDOWN_PATH, NULL};

        /* The log target defaults to console, but the original systemd process will pass its log target in through a
         * command line argument, which will override this default. Also, ensure we'll never log to the journal or
         * syslog, as these logging daemons are either already dead or will die very soon. */

        log_set_target(LOG_TARGET_CONSOLE);
        log_set_prohibit_ipc(true);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r < 0)
                goto error;

        log_open();

        umask(0022);

        if (getpid_cached() != 1) {
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
        else if (streq(arg_verb, "exit"))
                cmd = 0; /* ignored, just checking that arg_verb is valid */
        else {
                log_error("Unknown action '%s'.", arg_verb);
                r = -EINVAL;
                goto error;
        }

        (void) cg_get_root_path(&cgroup);
        in_container = detect_container() > 0;

        /* If the logging messages are going to KMSG, and if we are not running from a container, then try to
         * update the sysctl kernel.printk current value in order to see "info" messages; This current log
         * level is not updated if already big enough.
         */
        if (!in_container &&
            IN_SET(log_get_target(),
                   LOG_TARGET_AUTO,
                   LOG_TARGET_JOURNAL_OR_KMSG,
                   LOG_TARGET_SYSLOG_OR_KMSG,
                   LOG_TARGET_KMSG))
                bump_sysctl_printk_log_level(LOG_WARNING);

        use_watchdog = getenv("WATCHDOG_USEC");
        watchdog_device = getenv("WATCHDOG_DEVICE");
        if (watchdog_device) {
                r = watchdog_set_device(watchdog_device);
                if (r < 0)
                        log_warning_errno(r, "Failed to set watchdog device to %s, ignoring: %m",
                                          watchdog_device);
        }

        /* Lock us into memory */
        (void) mlockall(MCL_CURRENT|MCL_FUTURE);

        /* Synchronize everything that is not written to disk yet at this point already. This is a good idea so that
         * slow IO is processed here already and the final process killing spree is not impacted by processes
         * desperately trying to sync IO to disk within their timeout. Do not remove this sync, data corruption will
         * result. */
        if (!in_container)
                sync_with_progress();

        disable_coredumps();

        log_info("Sending SIGTERM to remaining processes...");
        broadcast_signal(SIGTERM, true, true, arg_timeout);

        log_info("Sending SIGKILL to remaining processes...");
        broadcast_signal(SIGKILL, true, false, arg_timeout);

        need_umount = !in_container;
        need_swapoff = !in_container;
        need_loop_detach = !in_container;
        need_dm_detach = !in_container;
        can_initrd = !in_container && !in_initrd() && access("/run/initramfs/shutdown", X_OK) == 0;

        /* Unmount all mountpoints, swaps, and loopback devices */
        for (;;) {
                bool changed = false;

                if (use_watchdog)
                        (void) watchdog_ping();

                /* Let's trim the cgroup tree on each iteration so
                   that we leave an empty cgroup tree around, so that
                   container managers get a nice notify event when we
                   are down */
                if (cgroup)
                        (void) cg_trim(SYSTEMD_CGROUP_CONTROLLER, cgroup, false);

                if (need_umount) {
                        log_info("Unmounting file systems.");
                        r = umount_all(&changed, umount_log_level);
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
                        r = loopback_detach_all(&changed, umount_log_level);
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
                        r = dm_detach_all(&changed, umount_log_level);
                        if (r == 0) {
                                need_dm_detach = false;
                                log_info("All DM devices detached.");
                        } else if (r > 0)
                                log_info("Not all DM devices detached, %d left.", r);
                        else
                                log_error_errno(r, "Failed to detach DM devices: %m");
                }

                if (!need_umount && !need_swapoff && !need_loop_detach && !need_dm_detach) {
                        log_info("All filesystems, swaps, loop devices and DM devices detached.");
                        /* Yay, done */
                        break;
                }

                if (!changed && umount_log_level == LOG_INFO && !can_initrd) {
                        /* There are things we cannot get rid of. Loop one more time
                         * with LOG_ERR to inform the user. Note that we don't need
                         * to do this if there is a initrd to switch to, because that
                         * one is likely to get rid of the remounting mounts. If not,
                         * it will log about them. */
                        umount_log_level = LOG_ERR;
                        continue;
                }

                /* If in this iteration we didn't manage to
                 * unmount/deactivate anything, we simply give up */
                if (!changed) {
                        log_info("Cannot finalize remaining%s%s%s%s continuing.",
                                 need_umount ? " file systems," : "",
                                 need_swapoff ? " swap devices," : "",
                                 need_loop_detach ? " loop devices," : "",
                                 need_dm_detach ? " DM devices," : "");
                        break;
                }

                log_debug("Couldn't finalize remaining %s%s%s%s trying again.",
                          need_umount ? " file systems," : "",
                          need_swapoff ? " swap devices," : "",
                          need_loop_detach ? " loop devices," : "",
                          need_dm_detach ? " DM devices," : "");
        }

        /* We're done with the watchdog. */
        watchdog_free_device();

        arguments[0] = NULL;
        arguments[1] = arg_verb;
        arguments[2] = NULL;
        (void) execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);

        (void) rlimit_nofile_safe();

        if (can_initrd) {
                r = switch_root_initramfs();
                if (r >= 0) {
                        argv[0] = (char*) "/shutdown";

                        (void) setsid();
                        (void) make_console_stdio();

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

        /* The kernel will automatically flush ATA disks and suchlike on reboot(), but the file systems need to be
         * sync'ed explicitly in advance. So let's do this here, but not needlessly slow down containers. Note that we
         * sync'ed things already once above, but we did some more work since then which might have caused IO, hence
         * let's do it once more. Do not remove this sync, data corruption will result. */
        if (!in_container)
                sync_with_progress();

        if (streq(arg_verb, "exit")) {
                if (in_container)
                        return arg_exit_code;

                cmd = RB_POWER_OFF; /* We cannot exit() on the host, fallback on another method. */
        }

        switch (cmd) {

        case LINUX_REBOOT_CMD_KEXEC:

                if (!in_container) {
                        /* We cheat and exec kexec to avoid doing all its work */
                        log_info("Rebooting with kexec.");

                        r = safe_fork("(sd-kexec)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_WAIT, NULL);
                        if (r == 0) {
                                const char * const args[] = {
                                        KEXEC, "-e", NULL
                                };

                                /* Child */

                                execv(args[0], (char * const *) args);
                                _exit(EXIT_FAILURE);
                        }

                        /* If we are still running, then the kexec can't have worked, let's fall through */
                }

                cmd = RB_AUTOBOOT;
                _fallthrough_;

        case RB_AUTOBOOT:
                (void) reboot_with_parameter(REBOOT_LOG);
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

        (void) reboot(cmd);
        if (errno == EPERM && in_container) {
                /* If we are in a container, and we lacked
                 * CAP_SYS_BOOT just exit, this will kill our
                 * container for good. */
                log_info("Exiting container.");
                return EXIT_SUCCESS;
        }

        r = log_error_errno(errno, "Failed to invoke reboot(): %m");

  error:
        log_emergency_errno(r, "Critical error while doing system shutdown: %m");
        freeze();
}
