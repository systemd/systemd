/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2004 Chris Friesen <chris_friesen@sympatico.ca>
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <getopt.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "mkdir.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "syslog-util.h"
#include "udev-manager.h"
#include "udev-util.h"
#include "udevd.h"
#include "version.h"

static bool arg_debug = false;
static int arg_daemonize = false;

static int listen_fds(int *ret_ctrl, int *ret_netlink) {
        int ctrl_fd = -EBADF, netlink_fd = -EBADF;
        int fd, n;

        assert(ret_ctrl);
        assert(ret_netlink);

        n = sd_listen_fds(true);
        if (n < 0)
                return n;

        for (fd = SD_LISTEN_FDS_START; fd < n + SD_LISTEN_FDS_START; fd++) {
                if (sd_is_socket(fd, AF_UNIX, SOCK_SEQPACKET, -1) > 0) {
                        if (ctrl_fd >= 0)
                                return -EINVAL;
                        ctrl_fd = fd;
                        continue;
                }

                if (sd_is_socket(fd, AF_NETLINK, SOCK_RAW, -1) > 0) {
                        if (netlink_fd >= 0)
                                return -EINVAL;
                        netlink_fd = fd;
                        continue;
                }

                return -EINVAL;
        }

        *ret_ctrl = ctrl_fd;
        *ret_netlink = netlink_fd;

        return 0;
}

static int manager_parse_udev_config(Manager *manager) {
        _cleanup_free_ char *log_val = NULL, *children_max = NULL, *exec_delay = NULL,
                *event_timeout = NULL, *resolve_names = NULL, *timeout_signal = NULL;
        int r;

        assert(manager);

        r = parse_env_file(NULL, "/etc/udev/udev.conf",
                           "udev_log", &log_val,
                           "children_max", &children_max,
                           "exec_delay", &exec_delay,
                           "event_timeout", &event_timeout,
                           "resolve_names", &resolve_names,
                           "timeout_signal", &timeout_signal);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        r = udev_set_max_log_level(log_val);
        if (r < 0)
                log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                           "Failed to set udev log level '%s', ignoring: %m", log_val);

        if (children_max) {
                r = safe_atou(children_max, &manager->children_max);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "Failed to parse children_max=%s, ignoring: %m", children_max);
        }

        if (exec_delay) {
                r = parse_sec(exec_delay, &manager->exec_delay_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "Failed to parse exec_delay=%s, ignoring: %m", exec_delay);
        }

        if (event_timeout) {
                r = parse_sec(event_timeout, &manager->timeout_usec);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "Failed to parse event_timeout=%s, ignoring: %m", event_timeout);
        }

        if (resolve_names) {
                ResolveNameTiming t;

                t = resolve_name_timing_from_string(resolve_names);
                if (t < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "Failed to parse resolve_names=%s, ignoring.", resolve_names);
                else
                        manager->resolve_name_timing = t;
        }

        if (timeout_signal) {
                r = signal_from_string(timeout_signal);
                if (r < 0)
                        log_syntax(NULL, LOG_WARNING, "/etc/udev/udev.conf", 0, r,
                                   "Failed to parse timeout_signal=%s, ignoring: %m", timeout_signal);
                else
                        manager->timeout_signal = r;
        }

        return 0;
}

/*
 * read the kernel command line, in case we need to get into debug mode
 *   udev.log_level=<level>                    syslog priority
 *   udev.children_max=<number of workers>     events are fully serialized if set to 1
 *   udev.exec_delay=<number of seconds>       delay execution of every executed program
 *   udev.event_timeout=<number of seconds>    seconds to wait before terminating an event
 *   udev.blockdev_read_only<=bool>            mark all block devices read-only when they appear
 */
static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        Manager *manager = ASSERT_PTR(data);
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "udev.log_level") ||
            proc_cmdline_key_streq(key, "udev.log_priority")) { /* kept for backward compatibility */

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r >= 0)
                        log_set_max_level(r);

        } else if (proc_cmdline_key_streq(key, "udev.event_timeout")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &manager->timeout_usec);

        } else if (proc_cmdline_key_streq(key, "udev.children_max")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou(value, &manager->children_max);

        } else if (proc_cmdline_key_streq(key, "udev.exec_delay")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &manager->exec_delay_usec);

        } else if (proc_cmdline_key_streq(key, "udev.timeout_signal")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = signal_from_string(value);
                if (r > 0)
                        manager->timeout_signal = r;

        } else if (proc_cmdline_key_streq(key, "udev.blockdev_read_only")) {

                if (!value)
                        manager->blockdev_read_only = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse udev.blockdev-read-only argument, ignoring: %s", value);
                        else
                                manager->blockdev_read_only = r;
                }

                if (manager->blockdev_read_only)
                        log_notice("All physical block devices will be marked read-only.");

                return 0;

        } else {
                if (startswith(key, "udev."))
                        log_warning("Unknown udev kernel command line option \"%s\", ignoring.", key);

                return 0;
        }

        if (r < 0)
                log_warning_errno(r, "Failed to parse \"%s=%s\", ignoring: %m", key, value);

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-udevd.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "Rule-based manager for device events and files.\n\n"
               "  -h --help                   Print this message\n"
               "  -V --version                Print version of the program\n"
               "  -d --daemon                 Detach and run in the background\n"
               "  -D --debug                  Enable debug output\n"
               "  -c --children-max=INT       Set maximum number of workers\n"
               "  -e --exec-delay=SECONDS     Seconds to wait before executing RUN=\n"
               "  -t --event-timeout=SECONDS  Seconds to wait before terminating an event\n"
               "  -N --resolve-names=early|late|never\n"
               "                              When to resolve users and groups\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[], Manager *manager) {
        enum {
                ARG_TIMEOUT_SIGNAL,
        };

        static const struct option options[] = {
                { "daemon",             no_argument,            NULL, 'd'                 },
                { "debug",              no_argument,            NULL, 'D'                 },
                { "children-max",       required_argument,      NULL, 'c'                 },
                { "exec-delay",         required_argument,      NULL, 'e'                 },
                { "event-timeout",      required_argument,      NULL, 't'                 },
                { "resolve-names",      required_argument,      NULL, 'N'                 },
                { "help",               no_argument,            NULL, 'h'                 },
                { "version",            no_argument,            NULL, 'V'                 },
                { "timeout-signal",     required_argument,      NULL,  ARG_TIMEOUT_SIGNAL },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);
        assert(manager);

        while ((c = getopt_long(argc, argv, "c:de:Dt:N:hV", options, NULL)) >= 0) {
                switch (c) {

                case 'd':
                        arg_daemonize = true;
                        break;
                case 'c':
                        r = safe_atou(optarg, &manager->children_max);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --children-max= value '%s', ignoring: %m", optarg);
                        break;
                case 'e':
                        r = parse_sec(optarg, &manager->exec_delay_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --exec-delay= value '%s', ignoring: %m", optarg);
                        break;
                case ARG_TIMEOUT_SIGNAL:
                        r = signal_from_string(optarg);
                        if (r <= 0)
                                log_warning_errno(r, "Failed to parse --timeout-signal= value '%s', ignoring: %m", optarg);
                        else
                                manager->timeout_signal = r;

                        break;
                case 't':
                        r = parse_sec(optarg, &manager->timeout_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --event-timeout= value '%s', ignoring: %m", optarg);
                        break;
                case 'D':
                        arg_debug = true;
                        break;
                case 'N': {
                        ResolveNameTiming t;

                        t = resolve_name_timing_from_string(optarg);
                        if (t < 0)
                                log_warning("Invalid --resolve-names= value '%s', ignoring.", optarg);
                        else
                                manager->resolve_name_timing = t;
                        break;
                }
                case 'h':
                        return help();
                case 'V':
                        printf("%s\n", GIT_VERSION);
                        return 0;
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();

                }
        }

        return 1;
}

int run_udevd(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        int fd_ctrl = -EBADF, fd_uevent = -EBADF;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_open();

        manager = manager_new();
        if (!manager)
                return log_oom();

        manager_parse_udev_config(manager);

        log_parse_environment();
        log_open(); /* Done again to update after reading configuration. */

        r = parse_argv(argc, argv, manager);
        if (r <= 0)
                return r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, manager, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (arg_debug) {
                log_set_target(LOG_TARGET_CONSOLE);
                log_set_max_level(LOG_DEBUG);
        }

        manager_adjust_arguments(manager);

        r = must_be_root();
        if (r < 0)
                return r;

        /* set umask before creating any file/directory */
        umask(022);

        r = mac_init();
        if (r < 0)
                return r;

        /* Make sure we can have plenty fds (for example for pidfds) */
        (void) rlimit_nofile_bump(-1);

        r = RET_NERRNO(mkdir("/run/udev", 0755));
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to create /run/udev: %m");

        r = listen_fds(&fd_ctrl, &fd_uevent);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on fds: %m");

        r = manager_init(manager, fd_ctrl, fd_uevent);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        if (arg_daemonize) {
                pid_t pid;

                log_info("Starting systemd-udevd version " GIT_VERSION);

                /* connect /dev/null to stdin, stdout, stderr */
                if (log_get_max_level() < LOG_DEBUG) {
                        r = make_null_stdio();
                        if (r < 0)
                                log_warning_errno(r, "Failed to redirect standard streams to /dev/null: %m");
                }

                pid = fork();
                if (pid < 0)
                        return log_error_errno(errno, "Failed to fork daemon: %m");
                if (pid > 0)
                        /* parent */
                        return 0;

                /* child */
                (void) setsid();
        }

        return manager_main(manager);
}
