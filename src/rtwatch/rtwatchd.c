/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-event.h"
#include "sd-json.h"

#include "build.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "conf-parser.h"
#include "daemon-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rtwatchd-dbus.h"
#include "rtwatchd-manager.h"
#include "rtwatchd-varlink.h"
#include "time-util.h"
#include "verbs.h"

static Settings arg_settings = SETTINGS_DEFAULT;

COMMAND(
        "systemd-rtwatchd\0",
        "Hand out realtime and high priority scheduling to unprivileged threads, safely.",
        .man_pages = "systemd-rtwatchd.service(8)\0",
);

/* The following parsers are used for both the command line and the configuration file. Relationships between
 * the settings are only validated once both have been parsed, see verify_settings(). */

static int parse_scheduling_policy(const char *s, int *ret) {
        int p;

        assert(s);
        assert(ret);

        p = sched_policy_from_string(s);
        if (!IN_SET(p, SCHED_RR, SCHED_FIFO))
                return -EINVAL;

        *ret = p;
        return 0;
}

static int parse_unsigned_positive(const char *s, unsigned *ret) {
        unsigned u;
        int r;

        assert(s);
        assert(ret);

        r = safe_atou(s, &u);
        if (r < 0)
                return r;
        if (u == 0)
                return -ERANGE;

        *ret = u;
        return 0;
}

static int parse_sec_positive(const char *s, usec_t *ret) {
        usec_t t;
        int r;

        assert(s);
        assert(ret);

        r = parse_sec(s, &t);
        if (r < 0)
                return r;
        if (t == 0 || t == USEC_INFINITY)
                return -ERANGE;

        *ret = t;
        return 0;
}

static int parse_rttime(const char *s, usec_t *ret) {
        rlim_t rl;
        int r;

        assert(s);
        assert(ret);

        /* Parse this the same way as LimitRTTIME= in unit files, i.e. in µs by default */
        r = rlimit_parse_one(RLIMIT_RTTIME, s, &rl);
        if (r < 0)
                return r;
        if (rl == 0 || rl == RLIM_INFINITY)
                return -ERANGE;

        *ret = rl;
        return 0;
}

static DEFINE_CONFIG_PARSE_PTR(config_parse_scheduling_policy, parse_scheduling_policy, int);
static DEFINE_CONFIG_PARSE_PTR(config_parse_nice_level, parse_nice, int);
static DEFINE_CONFIG_PARSE_PTR(config_parse_unsigned_positive, parse_unsigned_positive, unsigned);
static DEFINE_CONFIG_PARSE_PTR(config_parse_sec_positive, parse_sec_positive, usec_t);
static DEFINE_CONFIG_PARSE_PTR(config_parse_rttime, parse_rttime, usec_t);

static int parse_config(void) {
        const ConfigTableItem items[] = {
                { "RTWatch", "SchedulingPolicy",    config_parse_scheduling_policy, 0, &arg_settings.sched_policy           },
                { "RTWatch", "OurRealtimePriority", config_parse_int,               0, &arg_settings.our_realtime_priority  },
                { "RTWatch", "OurNiceLevel",        config_parse_nice_level,        0, &arg_settings.our_nice_level         },
                { "RTWatch", "MaxRealtimePriority", config_parse_int,               0, &arg_settings.max_realtime_priority  },
                { "RTWatch", "MinNiceLevel",        config_parse_nice_level,        0, &arg_settings.min_nice_level         },
                { "RTWatch", "RTTimeMax",           config_parse_rttime,            0, &arg_settings.rttime_max             },
                { "RTWatch", "UsersMax",            config_parse_unsigned_positive, 0, &arg_settings.users_max              },
                { "RTWatch", "ProcessesPerUserMax", config_parse_unsigned_positive, 0, &arg_settings.processes_per_user_max },
                { "RTWatch", "ThreadsPerUserMax",   config_parse_unsigned_positive, 0, &arg_settings.threads_per_user_max   },
                { "RTWatch", "ActionsBurstSec",     config_parse_sec_positive,      0, &arg_settings.actions_burst          },
                { "RTWatch", "ActionsPerBurstMax",  config_parse_unsigned_positive, 0, &arg_settings.actions_per_burst_max  },
                { "RTWatch", "Canary",              config_parse_bool,              0, &arg_settings.canary                 },
                { "RTWatch", "CanaryCheepSec",      config_parse_sec_positive,      0, &arg_settings.canary_cheep           },
                { "RTWatch", "CanaryWatchdogSec",   config_parse_sec_positive,      0, &arg_settings.canary_watchdog        },
                { "RTWatch", "CanaryRefuseSec",     config_parse_sec,               0, &arg_settings.canary_refuse          },
                { "RTWatch", "CanaryDemoteRoot",    config_parse_bool,              0, &arg_settings.canary_demote_root     },
                { "RTWatch", "CanaryDemoteUnknown", config_parse_bool,              0, &arg_settings.canary_demote_unknown  },
                {}
        };

        return config_parse_standard_file_with_dropins(
                        "systemd/rtwatchd.conf",
                        "RTWatch\0",
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL);
}

static int log_option_parse_error(int r, const char *optname, const char *s) {
        assert(optname);
        assert(s);

        if (r == -ERANGE)
                return log_error_errno(r, "Parameter %s out of range: %s", optname, s);

        return log_error_errno(r, "Failed to parse %s parameter: %s", optname, s);
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("bus-introspect", "PATH", "Write D-Bus XML introspection data"):
                        return bus_introspect_implementations(
                                        stdout,
                                        opts.arg,
                                        BUS_IMPLEMENTATIONS(&manager_object,
                                                            &log_control_object));

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);

                OPTION_LONG("scheduling-policy", "rr|fifo", "Realtime scheduling policy to hand out"):
                        r = parse_scheduling_policy(opts.arg, &arg_settings.sched_policy);
                        if (r < 0)
                                return log_option_parse_error(r, "--scheduling-policy=", opts.arg);
                        break;

                OPTION_LONG("our-realtime-priority", "PRIO", "Realtime priority of the daemon itself"):
                        r = safe_atoi(opts.arg, &arg_settings.our_realtime_priority);
                        if (r < 0)
                                return log_option_parse_error(r, "--our-realtime-priority=", opts.arg);
                        break;

                OPTION_LONG("our-nice-level", "NICE", "Nice level of the daemon itself"):
                        r = parse_nice(opts.arg, &arg_settings.our_nice_level);
                        if (r < 0)
                                return log_option_parse_error(r, "--our-nice-level=", opts.arg);
                        break;

                OPTION_LONG("max-realtime-priority", "PRIO", "Maximum realtime priority to hand out"):
                        r = safe_atoi(opts.arg, &arg_settings.max_realtime_priority);
                        if (r < 0)
                                return log_option_parse_error(r, "--max-realtime-priority=", opts.arg);
                        break;

                OPTION_LONG("min-nice-level", "NICE", "Minimum nice level to hand out"):
                        r = parse_nice(opts.arg, &arg_settings.min_nice_level);
                        if (r < 0)
                                return log_option_parse_error(r, "--min-nice-level=", opts.arg);
                        break;

                OPTION_LONG("rttime-max", "TIME", "Require clients to set RLIMIT_RTTIME no higher than this"):
                        r = parse_rttime(opts.arg, &arg_settings.rttime_max);
                        if (r < 0)
                                return log_option_parse_error(r, "--rttime-max=", opts.arg);
                        break;

                OPTION_LONG("users-max", "N", "Maximum number of users to supervise"):
                        r = parse_unsigned_positive(opts.arg, &arg_settings.users_max);
                        if (r < 0)
                                return log_option_parse_error(r, "--users-max=", opts.arg);
                        break;

                OPTION_LONG("processes-per-user-max", "N", "Maximum number of processes per user to supervise"):
                        r = parse_unsigned_positive(opts.arg, &arg_settings.processes_per_user_max);
                        if (r < 0)
                                return log_option_parse_error(r, "--processes-per-user-max=", opts.arg);
                        break;

                OPTION_LONG("threads-per-user-max", "N", "Maximum number of threads per user to supervise"):
                        r = parse_unsigned_positive(opts.arg, &arg_settings.threads_per_user_max);
                        if (r < 0)
                                return log_option_parse_error(r, "--threads-per-user-max=", opts.arg);
                        break;

                OPTION_LONG("actions-burst-sec", "TIME", "Time window for request rate limiting"):
                        r = parse_sec_positive(opts.arg, &arg_settings.actions_burst);
                        if (r < 0)
                                return log_option_parse_error(r, "--actions-burst-sec=", opts.arg);
                        break;

                OPTION_LONG("actions-per-burst-max", "N", "Maximum number of requests per user per time window"):
                        r = parse_unsigned_positive(opts.arg, &arg_settings.actions_per_burst_max);
                        if (r < 0)
                                return log_option_parse_error(r, "--actions-per-burst-max=", opts.arg);
                        break;

                OPTION_LONG("canary", "BOOL", "Run a canary based realtime watchdog"):
                        r = parse_boolean_argument("--canary=", opts.arg, &arg_settings.canary);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("canary-cheep-sec", "TIME", "Canary cheep interval"):
                        r = parse_sec_positive(opts.arg, &arg_settings.canary_cheep);
                        if (r < 0)
                                return log_option_parse_error(r, "--canary-cheep-sec=", opts.arg);
                        break;

                OPTION_LONG("canary-watchdog-sec", "TIME", "Watchdog timeout after which action is taken"):
                        r = parse_sec_positive(opts.arg, &arg_settings.canary_watchdog);
                        if (r < 0)
                                return log_option_parse_error(r, "--canary-watchdog-sec=", opts.arg);
                        break;

                OPTION_LONG("canary-refuse-sec", "TIME", "How long to refuse further requests after the canary starved"):
                        r = parse_sec(opts.arg, &arg_settings.canary_refuse);
                        if (r < 0)
                                return log_option_parse_error(r, "--canary-refuse-sec=", opts.arg);
                        break;

                OPTION_LONG("canary-demote-root", "BOOL", "Also demote root processes when the canary starved"):
                        r = parse_boolean_argument("--canary-demote-root=", opts.arg, &arg_settings.canary_demote_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("canary-demote-unknown", "BOOL", "Also demote unknown threads when the canary starved"):
                        r = parse_boolean_argument("--canary-demote-unknown=", opts.arg, &arg_settings.canary_demote_unknown);
                        if (r < 0)
                                return r;
                        break;
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1;
}

static int verify_settings(void) {

        /* The realtime priorities depend on the selected policy, and some settings depend on each other,
         * hence validate them only after parsing both the configuration file and the command line */

        if (!sched_priority_is_valid(arg_settings.sched_policy, arg_settings.our_realtime_priority))
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                       "Realtime priority of the daemon must be in the range %i…%i.",
                                       sched_get_priority_min_safe(arg_settings.sched_policy),
                                       sched_get_priority_max_safe(arg_settings.sched_policy));

        if (!sched_priority_is_valid(arg_settings.sched_policy, arg_settings.max_realtime_priority))
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                       "Maximum realtime priority must be in the range %i…%i.",
                                       sched_get_priority_min_safe(arg_settings.sched_policy),
                                       sched_get_priority_max_safe(arg_settings.sched_policy));

        if (arg_settings.max_realtime_priority >= arg_settings.our_realtime_priority)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The maximum realtime priority (%i) handed out to clients must be lower than our own (%i).",
                                       arg_settings.max_realtime_priority, arg_settings.our_realtime_priority);

        if (arg_settings.canary_cheep >= arg_settings.canary_watchdog)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The canary watchdog interval must be larger than the cheep interval.");

        return 0;
}

static int run(int argc, char *argv[]) {
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup();

        /* The command line takes precedence over the configuration file, hence parse it last */
        r = parse_config();
        if (r < 0)
                return r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = verify_settings();
        if (r < 0)
                return r;

        umask(0777);

        r = manager_new(&arg_settings, &m);
        if (r < 0)
                return r;

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        r = manager_connect_varlink(m);
        if (r < 0)
                return r;

        /* We pin every supervised process via a pidfd, hence make sure we can have many open */
        (void) rlimit_nofile_bump(/* limit= */ -1);

        r = manager_startup(m);
        if (r < 0)
                return r;

        notify_stop = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        manager_notify_status(m);

        r = sd_event_loop(m->event);

        /* Demote everything we know about before we exit, so that nothing is left at realtime priority
         * without our supervision */
        manager_reset_known(m);

        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
