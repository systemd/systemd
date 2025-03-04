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

static void manager_parse_udev_config(UdevConfig *config) {
        assert(config);

        const ConfigTableItem config_table[] = {
                { NULL, "udev_log",       config_parse_log_level,           0, &config->log_level           },
                { NULL, "children_max",   config_parse_unsigned,            0, &config->children_max        },
                { NULL, "exec_delay",     config_parse_sec,                 0, &config->exec_delay_usec     },
                { NULL, "event_timeout",  config_parse_sec,                 0, &config->timeout_usec        },
                { NULL, "resolve_names",  config_parse_resolve_name_timing, 0, &config->resolve_name_timing },
                { NULL, "timeout_signal", config_parse_signal,              0, &config->timeout_signal      },
                {}
        };

        (void) udev_parse_config_full(config_table);
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
        UdevConfig *config = ASSERT_PTR(data);
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "udev.log_level") ||
            proc_cmdline_key_streq(key, "udev.log_priority")) { /* kept for backward compatibility */

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r >= 0)
                        config->log_level = r;

        } else if (proc_cmdline_key_streq(key, "udev.event_timeout")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &config->timeout_usec);

        } else if (proc_cmdline_key_streq(key, "udev.children_max")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou(value, &config->children_max);

        } else if (proc_cmdline_key_streq(key, "udev.exec_delay")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_sec(value, &config->exec_delay_usec);

        } else if (proc_cmdline_key_streq(key, "udev.timeout_signal")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = signal_from_string(value);
                if (r > 0)
                        config->timeout_signal = r;

        } else if (proc_cmdline_key_streq(key, "udev.blockdev_read_only")) {

                if (!value)
                        config->blockdev_read_only = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse udev.blockdev-read-only argument, ignoring: %s", value);
                        else
                                config->blockdev_read_only = r;
                }

                if (config->blockdev_read_only)
                        log_notice("All physical block devices will be marked read-only.");

                return 0;

        } else if (proc_cmdline_key_streq(key, "udev.trace")) {

                if (!value)
                        config->trace = true;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse udev.trace argument, ignoring: %s", value);
                        else
                                config->trace = r;
                }

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

static int parse_argv(int argc, char *argv[], UdevConfig *config) {
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
        assert(config);

        while ((c = getopt_long(argc, argv, "c:de:Dt:N:hV", options, NULL)) >= 0) {
                switch (c) {

                case 'd':
                        arg_daemonize = true;
                        break;
                case 'c':
                        r = safe_atou(optarg, &config->children_max);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --children-max= value '%s', ignoring: %m", optarg);
                        break;
                case 'e':
                        r = parse_sec(optarg, &config->exec_delay_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --exec-delay= value '%s', ignoring: %m", optarg);
                        break;
                case ARG_TIMEOUT_SIGNAL:
                        r = signal_from_string(optarg);
                        if (r <= 0)
                                log_warning_errno(r, "Failed to parse --timeout-signal= value '%s', ignoring: %m", optarg);
                        else
                                config->timeout_signal = r;

                        break;
                case 't':
                        r = parse_sec(optarg, &config->timeout_usec);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse --event-timeout= value '%s', ignoring: %m", optarg);
                        break;
                case 'D':
                        arg_debug = true;
                        config->log_level = LOG_DEBUG;
                        break;
                case 'N': {
                        ResolveNameTiming t;

                        t = resolve_name_timing_from_string(optarg);
                        if (t < 0)
                                log_warning("Invalid --resolve-names= value '%s', ignoring.", optarg);
                        else
                                config->resolve_name_timing = t;
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

#define MERGE_NON_NEGATIVE(name, default_value)                                              \
        manager->config.name =                                                               \
                manager->config_by_control.name >= 0 ? manager->config_by_control.name :     \
                manager->config_by_kernel.name >= 0 ? manager->config_by_kernel.name :       \
                manager->config_by_command.name >= 0 ? manager->config_by_command.name :     \
                manager->config_by_udev_conf.name >= 0 ? manager->config_by_udev_conf.name : \
                default_value;

#define MERGE_NON_ZERO(name, default_value)                             \
        manager->config.name =                                          \
                manager->config_by_control.name ?:                      \
                manager->config_by_kernel.name ?:                       \
                manager->config_by_command.name ?:                      \
                manager->config_by_udev_conf.name ?:                    \
                default_value;

#define MERGE_BOOL(name) \
        manager->config.name =                                          \
                manager->config_by_control.name ||                      \
                manager->config_by_kernel.name ||                       \
                manager->config_by_command.name ||                      \
                manager->config_by_udev_conf.name;

static void manager_merge_config_log_level(Manager *manager) {
        assert(manager);

        MERGE_BOOL(trace);

        if (manager->config.trace)
                manager->config.log_level = LOG_DEBUG;
        else
                MERGE_NON_NEGATIVE(log_level, log_get_max_level());
}

static void manager_merge_config(Manager *manager) {
        assert(manager);

        /* udev.conf has the lowest priority, then followed by command line arguments, kernel command line
           options, and values set by udev control. */

        manager_merge_config_log_level(manager);
        MERGE_NON_NEGATIVE(resolve_name_timing, RESOLVE_NAME_EARLY);
        MERGE_NON_ZERO(exec_delay_usec, 0);
        MERGE_NON_ZERO(timeout_usec, DEFAULT_WORKER_TIMEOUT_USEC);
        MERGE_NON_ZERO(timeout_signal, SIGKILL);
        MERGE_BOOL(blockdev_read_only);
}

static void udev_config_set_default_children_max(UdevConfig *config) {
        uint64_t cpu_limit, mem_limit, cpu_count = 1;
        int r;

        assert(config);

        if (config->children_max != 0)
                return;

        r = cpus_in_affinity_mask();
        if (r < 0)
                log_warning_errno(r, "Failed to determine number of local CPUs, ignoring: %m");
        else
                cpu_count = r;

        cpu_limit = cpu_count * 2 + 16;
        mem_limit = MAX(physical_memory() / (128*1024*1024), UINT64_C(10));

        config->children_max = MIN3(cpu_limit, mem_limit, WORKER_NUM_MAX);
        log_debug("Set children_max to %u", config->children_max);
}

void manager_set_children_max(Manager *manager, unsigned n) {
        assert(manager);

        manager->config_by_control.children_max = n;
        /* When 0 is specified, determine the maximum based on the system resources. */
        udev_config_set_default_children_max(&manager->config_by_control);
        manager->config.children_max = manager->config_by_control.children_max;

        notify_ready(manager);
}

void manager_set_log_level(Manager *manager, int log_level) {
        assert(manager);
        assert(log_level_is_valid(log_level));

        int old = log_get_max_level();

        manager->config_by_control.log_level = log_level;
        manager_merge_config_log_level(manager);

        if (manager->config.log_level == old)
                return;

        log_set_max_level(manager->config.log_level);
        manager_kill_workers(manager, /* force = */ false);
}

void manager_set_trace(Manager *manager, bool enable) {
        assert(manager);

        bool old = manager->config.trace;

        manager->config_by_control.trace = enable;
        manager_merge_config_log_level(manager);

        if (manager->config.trace == old)
                return;

        log_set_max_level(manager->config.log_level);
        manager_kill_workers(manager, /* force = */ false);
}

static void manager_adjust_config(UdevConfig *config) {
        assert(config);

        log_set_max_level(config->log_level);

        if (config->timeout_usec < MIN_WORKER_TIMEOUT_USEC) {
                log_debug("Timeout (%s) for processing event is too small, using the default: %s",
                          FORMAT_TIMESPAN(config->timeout_usec, 1),
                          FORMAT_TIMESPAN(DEFAULT_WORKER_TIMEOUT_USEC, 1));

                config->timeout_usec = DEFAULT_WORKER_TIMEOUT_USEC;
        }

        if (config->exec_delay_usec >= config->timeout_usec) {
                log_debug("Delay (%s) for executing RUN= commands is too large compared with the timeout (%s) for event execution, ignoring the delay.",
                          FORMAT_TIMESPAN(config->exec_delay_usec, 1),
                          FORMAT_TIMESPAN(config->timeout_usec, 1));

                config->exec_delay_usec = 0;
        }

        udev_config_set_default_children_max(config);
}

static int manager_set_environment_one(Manager *manager, const char *s) {
        int r;

        assert(manager);
        assert(s);

        _cleanup_free_ char *key = NULL, *value = NULL;
        r = split_pair(s, "=", &key, &value);
        if (r < 0)
                return r;

        if (isempty(value)) {
                _cleanup_free_ char *old_key = NULL, *old_value = NULL;
                old_value = hashmap_remove2(manager->properties, key, (void**) &old_key);
                return !!old_value;
        }

        if (streq_ptr(value, hashmap_get(manager->properties, key)))
                return 0;

        _cleanup_free_ char *old_key = NULL, *old_value = NULL;
        old_value = hashmap_get2(manager->properties, key, (void**) &old_key);

        r = hashmap_ensure_replace(&manager->properties, &string_hash_ops_free_free, key, value);
        if (r < 0) {
                assert(!old_key);
                assert(!old_value);
                return r;
        }

        TAKE_PTR(key);
        TAKE_PTR(value);
        return 1;
}

void manager_set_environment(Manager *manager, char * const *v) {
        bool changed = false;
        int r;

        assert(manager);

        STRV_FOREACH(s, v) {
                r = manager_set_environment_one(manager, *s);
                if (r < 0)
                        log_debug_errno(r, "Failed to update environment '%s', ignoring: %m", *s);
                changed = changed || r > 0;
        }

        if (changed)
                manager_kill_workers(manager, /* force = */ false);
}

int manager_load(Manager *manager, int argc, char *argv[]) {
        int r;

        assert(manager);

        manager_parse_udev_config(&manager->config_by_udev_conf);

        r = parse_argv(argc, argv, &manager->config_by_command);
        if (r <= 0)
                return r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, &manager->config_by_kernel, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        manager_merge_config(manager);

        if (arg_debug)
                log_set_target(LOG_TARGET_CONSOLE);

        manager_adjust_config(&manager->config);
        return 1;
}

UdevReloadFlags manager_reload_config(Manager *manager) {
        assert(manager);

        UdevConfig old = manager->config;

        manager->config_by_udev_conf = UDEV_CONFIG_INIT;
        manager_parse_udev_config(&manager->config_by_udev_conf);
        manager_merge_config(manager);
        manager_adjust_config(&manager->config);

        if (manager->config.resolve_name_timing != old.resolve_name_timing)
                return UDEV_RELOAD_RULES | UDEV_RELOAD_KILL_WORKERS;

        if (manager->config.log_level != old.log_level ||
            manager->config.exec_delay_usec != old.exec_delay_usec ||
            manager->config.timeout_usec != old.timeout_usec ||
            manager->config.timeout_signal != old.timeout_signal ||
            manager->config.blockdev_read_only != old.blockdev_read_only ||
            manager->config.trace != old.trace)
                return UDEV_RELOAD_KILL_WORKERS;

        return 0;
}
