/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010-2017 Canonical
  Copyright © 2018 Dell Inc.
***/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/fiemap.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-messages.h"

#include "btrfs-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "constants.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "io-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "sleep-config.h"
#include "special.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"

static SleepOperation arg_operation = _SLEEP_OPERATION_INVALID;

static int write_hibernate_location_info(const HibernateLocation *hibernate_location) {
        char offset_str[DECIMAL_STR_MAX(uint64_t)];
        char resume_str[DECIMAL_STR_MAX(unsigned) * 2 + STRLEN(":")];
        int r;

        assert(hibernate_location);
        assert(hibernate_location->swap);

        xsprintf(resume_str, "%u:%u", major(hibernate_location->devno), minor(hibernate_location->devno));
        r = write_string_file("/sys/power/resume", resume_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write partition device to /sys/power/resume for '%s': '%s': %m",
                                       hibernate_location->swap->device, resume_str);

        log_debug("Wrote resume= value for %s to /sys/power/resume: %s", hibernate_location->swap->device, resume_str);

        /* if it's a swap partition, we're done */
        if (streq(hibernate_location->swap->type, "partition"))
                return r;

        if (!streq(hibernate_location->swap->type, "file"))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid hibernate type: %s", hibernate_location->swap->type);

        /* Only available in 4.17+ */
        if (hibernate_location->offset > 0 && access("/sys/power/resume_offset", W_OK) < 0) {
                if (errno == ENOENT) {
                        log_debug("Kernel too old, can't configure resume_offset for %s, ignoring: %" PRIu64,
                                  hibernate_location->swap->device, hibernate_location->offset);
                        return 0;
                }

                return log_debug_errno(errno, "/sys/power/resume_offset not writable: %m");
        }

        xsprintf(offset_str, "%" PRIu64, hibernate_location->offset);
        r = write_string_file("/sys/power/resume_offset", offset_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write swap file offset to /sys/power/resume_offset for '%s': '%s': %m",
                                       hibernate_location->swap->device, offset_str);

        log_debug("Wrote resume_offset= value for %s to /sys/power/resume_offset: %s", hibernate_location->swap->device, offset_str);

        return 0;
}

static int write_mode(char **modes) {
        int r = 0;

        STRV_FOREACH(mode, modes) {
                int k;

                k = write_string_file("/sys/power/disk", *mode, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (k >= 0)
                        return 0;

                log_debug_errno(k, "Failed to write '%s' to /sys/power/disk: %m", *mode);
                if (r >= 0)
                        r = k;
        }

        return r;
}

static int write_state(FILE **f, char **states) {
        int r = 0;

        assert(f);
        assert(*f);

        STRV_FOREACH(state, states) {
                int k;

                k = write_string_stream(*f, *state, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (k >= 0)
                        return 0;
                log_debug_errno(k, "Failed to write '%s' to /sys/power/state: %m", *state);
                if (r >= 0)
                        r = k;

                fclose(*f);
                *f = fopen("/sys/power/state", "we");
                if (!*f)
                        return -errno;
        }

        return r;
}

static int lock_all_homes(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        /* Let's synchronously lock all home directories managed by homed that have been marked for it. This
         * way the key material required to access these volumes is hopefully removed from memory. */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_warning_errno(r, "Failed to connect to system bus, ignoring: %m");

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.home1",
                        "/org/freedesktop/home1",
                        "org.freedesktop.home1.Manager",
                        "LockAllHomes");
        if (r < 0)
                return bus_log_create_error(r);

        /* If homed is not running it can't have any home directories active either. */
        r = sd_bus_message_set_auto_start(m, false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable auto-start of LockAllHomes() message: %m");

        r = sd_bus_call(bus, m, DEFAULT_TIMEOUT_USEC, &error, NULL);
        if (r < 0) {
                if (!bus_error_is_unknown_service(&error))
                        return log_error_errno(r, "Failed to lock home directories: %s", bus_error_message(&error, r));

                log_debug("systemd-homed is not running, locking of home directories skipped.");
        } else
                log_debug("Successfully requested locking of all home directories.");
        return 0;
}

static int execute(
                const SleepConfig *sleep_config,
                SleepOperation operation,
                const char *action) {

        char *arguments[] = {
                NULL,
                (char*) "pre",
                /* NB: we use 'arg_operation' instead of 'operation' here, as we want to communicate the overall
                 * operation here, not the specific one, in case of s2h. */
                (char*) sleep_operation_to_string(arg_operation),
                NULL
        };
        static const char* const dirs[] = {
                SYSTEM_SLEEP_PATH,
                NULL
        };

        _cleanup_(hibernate_location_freep) HibernateLocation *hibernate_location = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        char **modes, **states;
        int r;

        assert(sleep_config);
        assert(operation >= 0);
        assert(operation < _SLEEP_OPERATION_MAX);
        assert(operation != SLEEP_SUSPEND_THEN_HIBERNATE); /* Handled by execute_s2h() instead */

        states = sleep_config->states[operation];
        modes = sleep_config->modes[operation];

        if (strv_isempty(states))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No sleep states configured for sleep operation %s, can't sleep.",
                                       sleep_operation_to_string(operation));

        /* This file is opened first, so that if we hit an error,
         * we can abort before modifying any state. */
        f = fopen("/sys/power/state", "we");
        if (!f)
                return log_error_errno(errno, "Failed to open /sys/power/state: %m");

        setvbuf(f, NULL, _IONBF, 0);

        /* Configure hibernation settings if we are supposed to hibernate */
        if (!strv_isempty(modes)) {
                r = find_hibernate_location(&hibernate_location);
                if (r < 0)
                        return log_error_errno(r, "Failed to find location to hibernate to: %m");
                if (r == 0) { /* 0 means: no hibernation location was configured in the kernel so far, let's
                               * do it ourselves then. > 0 means: kernel already had a configured hibernation
                               * location which we shouldn't touch. */
                        r = write_hibernate_location_info(hibernate_location);
                        if (r < 0)
                                return log_error_errno(r, "Failed to prepare for hibernation: %m");
                }

                r = write_mode(modes);
                if (r < 0)
                        return log_error_errno(r, "Failed to write mode to /sys/power/disk: %m");
        }

        /* Pass an action string to the call-outs. This is mostly our operation string, except if the
         * hibernate step of s-t-h fails, in which case we communicate that with a separate action. */
        if (!action)
                action = sleep_operation_to_string(operation);

        r = setenv("SYSTEMD_SLEEP_ACTION", action, 1);
        if (r != 0)
                log_warning_errno(errno, "Error setting SYSTEMD_SLEEP_ACTION=%s, ignoring: %m", action);

        (void) execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);
        (void) lock_all_homes();

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_SLEEP_START_STR,
                   LOG_MESSAGE("Entering sleep state '%s'...", sleep_operation_to_string(operation)),
                   "SLEEP=%s", sleep_operation_to_string(arg_operation));

        r = write_state(&f, states);
        if (r < 0)
                log_struct_errno(LOG_ERR, r,
                                 "MESSAGE_ID=" SD_MESSAGE_SLEEP_STOP_STR,
                                 LOG_MESSAGE("Failed to put system to sleep. System resumed again: %m"),
                                 "SLEEP=%s", sleep_operation_to_string(arg_operation));
        else
                log_struct(LOG_INFO,
                           "MESSAGE_ID=" SD_MESSAGE_SLEEP_STOP_STR,
                           LOG_MESSAGE("System returned from sleep state."),
                           "SLEEP=%s", sleep_operation_to_string(arg_operation));

        arguments[1] = (char*) "post";
        (void) execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments, NULL, EXEC_DIR_PARALLEL | EXEC_DIR_IGNORE_ERRORS);

        return r;
}

static int custom_timer_suspend(const SleepConfig *sleep_config) {
        usec_t hibernate_timestamp;
        int r;

        assert(sleep_config);

        hibernate_timestamp = usec_add(now(CLOCK_BOOTTIME), sleep_config->hibernate_delay_usec);

        while (battery_is_discharging_and_low() == 0) {
                _cleanup_hashmap_free_ Hashmap *last_capacity = NULL, *current_capacity = NULL;
                _cleanup_close_ int tfd = -EBADF;
                struct itimerspec ts = {};
                usec_t suspend_interval;
                bool woken_by_timer;

                tfd = timerfd_create(CLOCK_BOOTTIME_ALARM, TFD_NONBLOCK|TFD_CLOEXEC);
                if (tfd < 0)
                        return log_error_errno(errno, "Error creating timerfd: %m");

                /* Store current battery capacity before suspension */
                r = fetch_batteries_capacity_by_name(&last_capacity);
                if (r < 0)
                        return log_error_errno(r, "Error fetching battery capacity percentage: %m");

                if (hashmap_isempty(last_capacity))
                        /* In case of no battery, system suspend interval will be set to HibernateDelaySec= or 2 hours. */
                        suspend_interval = timestamp_is_set(hibernate_timestamp) ? sleep_config->hibernate_delay_usec : DEFAULT_SUSPEND_ESTIMATION_USEC;
                else {
                        r = get_total_suspend_interval(last_capacity, &suspend_interval);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to estimate suspend interval using previous discharge rate, ignoring: %m");
                                /* In case of any errors, especially when we do not know the battery
                                 * discharging rate, system suspend interval will be set to
                                 * SuspendEstimationSec=. */
                                suspend_interval = sleep_config->suspend_estimation_usec;
                        }
                }

                /* Do not suspend more than HibernateDelaySec= */
                usec_t before_timestamp = now(CLOCK_BOOTTIME);
                suspend_interval = MIN(suspend_interval, usec_sub_unsigned(hibernate_timestamp, before_timestamp));
                if (suspend_interval <= 0)
                        break; /* system should hibernate */

                log_debug("Set timerfd wake alarm for %s", FORMAT_TIMESPAN(suspend_interval, USEC_PER_SEC));
                /* Wake alarm for system with or without battery to hibernate or estimate discharge rate whichever is applicable */
                timespec_store(&ts.it_value, suspend_interval);

                if (timerfd_settime(tfd, 0, &ts, NULL) < 0)
                        return log_error_errno(errno, "Error setting battery estimate timer: %m");

                r = execute(sleep_config, SLEEP_SUSPEND, NULL);
                if (r < 0)
                        return r;

                r = fd_wait_for_event(tfd, POLLIN, 0);
                if (r < 0)
                        return log_error_errno(r, "Error polling timerfd: %m");
                /* Store fd_wait status */
                woken_by_timer = FLAGS_SET(r, POLLIN);

                r = fetch_batteries_capacity_by_name(&current_capacity);
                if (r < 0 || hashmap_isempty(current_capacity)) {
                        /* In case of no battery or error while getting charge level, no need to measure
                         * discharge rate. Instead the system should wake up if it is manual wakeup or
                         * hibernate if this is a timer wakeup. */
                        if (r < 0)
                                log_debug_errno(r, "Battery capacity percentage unavailable, cannot estimate discharge rate: %m");
                        else
                                log_debug("No battery found.");
                        if (!woken_by_timer)
                                return 0;
                        break;
                }

                usec_t after_timestamp = now(CLOCK_BOOTTIME);
                log_debug("Attempting to estimate battery discharge rate after wakeup from %s sleep",
                          FORMAT_TIMESPAN(after_timestamp - before_timestamp, USEC_PER_HOUR));

                if (after_timestamp != before_timestamp) {
                        r = estimate_battery_discharge_rate_per_hour(last_capacity, current_capacity, before_timestamp, after_timestamp);
                        if (r < 0)
                                log_warning_errno(r, "Failed to estimate and update battery discharge rate, ignoring: %m");
                } else
                        log_debug("System woke up too early to estimate discharge rate");

                if (!woken_by_timer)
                        /* Return as manual wakeup done. This also will return in case battery was charged during suspension */
                        return 0;

                r = check_wakeup_type();
                if (r < 0)
                        log_debug_errno(r, "Failed to check hardware wakeup type, ignoring: %m");
                if (r > 0) {
                        log_debug("wakeup type is APM timer");
                        /* system should hibernate */
                        break;
                }
        }

        return 1;
}

/* Freeze when invoked and thaw on cleanup */
static int freeze_thaw_user_slice(const char **method) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        if (!method || !*method)
                return 0;

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to open connection to systemd: %m");

        /* Wait for 1.5 seconds at maximum for freeze operation */
        (void) sd_bus_set_method_call_timeout(bus, 1500 * USEC_PER_MSEC);

        r = bus_call_method(bus, bus_systemd_mgr, *method, &error, NULL, "s", SPECIAL_USER_SLICE);
        if (r < 0)
                return log_debug_errno(r, "Failed to execute operation: %s", bus_error_message(&error, r));

        return 1;
}

static int execute_s2h(const SleepConfig *sleep_config) {
        _unused_ _cleanup_(freeze_thaw_user_slice) const char *auto_method_thaw = "ThawUnit";
        int r;

        assert(sleep_config);

        r = freeze_thaw_user_slice(&(const char*) { "FreezeUnit" });
        if (r < 0)
                log_debug_errno(r, "Failed to freeze unit user.slice, ignoring: %m");

        /* Only check if we have automated battery alarms if HibernateDelaySec= is not set, as in that case
         * we'll busy poll for the configured interval instead */
        if (!timestamp_is_set(sleep_config->hibernate_delay_usec)) {
                r = check_wakeup_type();
                if (r < 0)
                        log_debug_errno(r, "Failed to check hardware wakeup type, ignoring: %m");
                else {
                        r = battery_trip_point_alarm_exists();
                        if (r < 0)
                                log_debug_errno(r, "Failed to check whether acpi_btp support is enabled or not, ignoring: %m");
                }
        } else
                r = 0;  /* Force fallback path */

        if (r > 0) { /* If we have both wakeup alarms and battery trip point support, use them */
                log_debug("Attempting to suspend...");
                r = execute(sleep_config, SLEEP_SUSPEND, NULL);
                if (r < 0)
                        return r;

                r = check_wakeup_type();
                if (r < 0)
                        return log_debug_errno(r, "Failed to check hardware wakeup type: %m");

                if (r == 0)
                        /* For APM Timer wakeup, system should hibernate else wakeup */
                        return 0;
        } else {
                r = custom_timer_suspend(sleep_config);
                if (r < 0)
                        return log_debug_errno(r, "Suspend cycle with manual battery discharge rate estimation failed: %m");
                if (r == 0)
                        /* manual wakeup */
                        return 0;
        }
        /* For above custom timer, if 1 is returned, system will directly hibernate */

        log_debug("Attempting to hibernate");
        r = execute(sleep_config, SLEEP_HIBERNATE, NULL);
        if (r < 0) {
                log_notice("Couldn't hibernate, will try to suspend again.");

                r = execute(sleep_config, SLEEP_SUSPEND, "suspend-after-failed-hibernate");
                if (r < 0)
                        return r;
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-suspend.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s COMMAND\n\n"
               "Suspend the system, hibernate the system, or both.\n\n"
               "  -h --help              Show this help and exit\n"
               "  --version              Print version string and exit\n"
               "\nCommands:\n"
               "  suspend                Suspend the system\n"
               "  hibernate              Hibernate the system\n"
               "  hybrid-sleep           Both hibernate and suspend the system\n"
               "  suspend-then-hibernate Initially suspend and then hibernate\n"
               "                         the system after a fixed period of time\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version",      no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc - optind != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Usage: %s COMMAND",
                                       program_invocation_short_name);

        arg_operation = sleep_operation_from_string(argv[optind]);
        if (arg_operation < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command '%s'.", argv[optind]);

        return 1 /* work to do */;
}

static int run(int argc, char *argv[]) {
        _cleanup_(free_sleep_configp) SleepConfig *sleep_config = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_sleep_config(&sleep_config);
        if (r < 0)
                return r;

        if (!sleep_config->allow[arg_operation])
                return log_error_errno(SYNTHETIC_ERRNO(EACCES),
                                       "Sleep operation \"%s\" is disabled by configuration, refusing.",
                                       sleep_operation_to_string(arg_operation));

        switch (arg_operation) {

        case SLEEP_SUSPEND_THEN_HIBERNATE:
                r = execute_s2h(sleep_config);
                break;

        case SLEEP_HYBRID_SLEEP:
                r = execute(sleep_config, SLEEP_HYBRID_SLEEP, NULL);
                if (r < 0) {
                        /* If we can't hybrid sleep, then let's try to suspend at least. After all, the user
                         * asked us to do both: suspend + hibernate, and it's almost certainly the
                         * hibernation that failed, hence still do the other thing, the suspend. */

                        log_notice("Couldn't hybrid sleep, will try to suspend instead.");

                        r = execute(sleep_config, SLEEP_SUSPEND, "suspend-after-failed-hybrid-sleep");
                }

                break;

        default:
                r = execute(sleep_config, arg_operation, NULL);
                break;
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
