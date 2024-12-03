/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <unistd.h>

#include "conf-parser.h"
#include "cpu-set-util.h"
#include "limits-util.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "signal-util.h"
#include "syslog-util.h"
#include "udev-config.h"
#include "udev-manager.h"
#include "udev-rules.h"
#include "udev-util.h"
#include "udev-worker.h"
#include "version.h"

#define WORKER_NUM_MAX UINT64_C(2048)

static bool arg_debug = false;
bool arg_daemonize = false;

static DEFINE_CONFIG_PARSE_ENUM(config_parse_resolve_name_timing, resolve_name_timing, ResolveNameTiming);

static int manager_parse_udev_config(Manager *manager) {
        int r, log_val = -1;

        assert(manager);

        const ConfigTableItem config_table[] = {
                { NULL, "udev_log",       config_parse_log_level,           0, &log_val                      },
                { NULL, "children_max",   config_parse_unsigned,            0, &manager->children_max        },
                { NULL, "exec_delay",     config_parse_sec,                 0, &manager->exec_delay_usec     },
                { NULL, "event_timeout",  config_parse_sec,                 0, &manager->timeout_usec        },
                { NULL, "resolve_names",  config_parse_resolve_name_timing, 0, &manager->resolve_name_timing },
                { NULL, "timeout_signal", config_parse_signal,              0, &manager->timeout_signal      },
                {}
        };

        r = udev_parse_config_full(config_table);
        if (r < 0)
                return r;

        if (log_val >= 0)
                log_set_max_level(log_val);

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
                        manager->log_level = r;

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

void manager_set_default_children_max(Manager *manager) {
        uint64_t cpu_limit, mem_limit, cpu_count = 1;
        int r;

        assert(manager);

        if (manager->children_max != 0)
                return;

        r = cpus_in_affinity_mask();
        if (r < 0)
                log_warning_errno(r, "Failed to determine number of local CPUs, ignoring: %m");
        else
                cpu_count = r;

        cpu_limit = cpu_count * 2 + 16;
        mem_limit = MAX(physical_memory() / (128*1024*1024), UINT64_C(10));

        manager->children_max = MIN3(cpu_limit, mem_limit, WORKER_NUM_MAX);
        log_debug("Set children_max to %u", manager->children_max);
}

static void manager_adjust_config(Manager *manager) {
        assert(manager);

        if (manager->timeout_usec < MIN_WORKER_TIMEOUT_USEC) {
                log_debug("Timeout (%s) for processing event is too small, using the default: %s",
                          FORMAT_TIMESPAN(manager->timeout_usec, 1),
                          FORMAT_TIMESPAN(DEFAULT_WORKER_TIMEOUT_USEC, 1));

                manager->timeout_usec = DEFAULT_WORKER_TIMEOUT_USEC;
        }

        if (manager->exec_delay_usec >= manager->timeout_usec) {
                log_debug("Delay (%s) for executing RUN= commands is too large compared with the timeout (%s) for event execution, ignoring the delay.",
                          FORMAT_TIMESPAN(manager->exec_delay_usec, 1),
                          FORMAT_TIMESPAN(manager->timeout_usec, 1));

                manager->exec_delay_usec = 0;
        }

        manager_set_default_children_max(manager);
}

int manager_load(Manager *manager, int argc, char *argv[]) {
        int r;

        assert(manager);

        manager_parse_udev_config(manager);

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

        manager_adjust_config(manager);
        return 1;
}
