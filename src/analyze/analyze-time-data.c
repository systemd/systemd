/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze-time-data.h"
#include "analyze.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "memory-util.h"
#include "special.h"
#include "strv.h"

static void subtract_timestamp(usec_t *a, usec_t b) {
        assert(a);

        if (*a > 0) {
                assert(*a >= b);
                *a -= b;
        }
}

static int log_not_finished(usec_t finish_time) {
        return log_error_errno(SYNTHETIC_ERRNO(EINPROGRESS),
                               "Bootup is not yet finished (org.freedesktop.systemd1.Manager.FinishTimestampMonotonic=%"PRIu64").\n"
                               "Please try again later.\n"
                               "Hint: Use 'systemctl%s list-jobs' to see active jobs",
                               finish_time,
                               arg_runtime_scope == RUNTIME_SCOPE_SYSTEM ? "" : " --user");
}

int acquire_boot_times(sd_bus *bus, bool require_finished, BootTimes **ret) {
        static const struct bus_properties_map property_map[] = {
                { "FirmwareTimestampMonotonic",               "t", NULL, offsetof(BootTimes, firmware_time)                 },
                { "LoaderTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, loader_time)                   },
                { "KernelTimestamp",                          "t", NULL, offsetof(BootTimes, kernel_time)                   },
                { "InitRDTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, initrd_time)                   },
                { "UserspaceTimestampMonotonic",              "t", NULL, offsetof(BootTimes, userspace_time)                },
                { "FinishTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, finish_time)                   },
                { "SecurityStartTimestampMonotonic",          "t", NULL, offsetof(BootTimes, security_start_time)           },
                { "SecurityFinishTimestampMonotonic",         "t", NULL, offsetof(BootTimes, security_finish_time)          },
                { "ShutdownStartTimestampMonotonic",          "t", NULL, offsetof(BootTimes, shutdown_start_time)           },
                { "GeneratorsStartTimestampMonotonic",        "t", NULL, offsetof(BootTimes, generators_start_time)         },
                { "GeneratorsFinishTimestampMonotonic",       "t", NULL, offsetof(BootTimes, generators_finish_time)        },
                { "UnitsLoadStartTimestampMonotonic",         "t", NULL, offsetof(BootTimes, unitsload_start_time)          },
                { "UnitsLoadFinishTimestampMonotonic",        "t", NULL, offsetof(BootTimes, unitsload_finish_time)         },
                { "InitRDSecurityStartTimestampMonotonic",    "t", NULL, offsetof(BootTimes, initrd_security_start_time)    },
                { "InitRDSecurityFinishTimestampMonotonic",   "t", NULL, offsetof(BootTimes, initrd_security_finish_time)   },
                { "InitRDGeneratorsStartTimestampMonotonic",  "t", NULL, offsetof(BootTimes, initrd_generators_start_time)  },
                { "InitRDGeneratorsFinishTimestampMonotonic", "t", NULL, offsetof(BootTimes, initrd_generators_finish_time) },
                { "InitRDUnitsLoadStartTimestampMonotonic",   "t", NULL, offsetof(BootTimes, initrd_unitsload_start_time)   },
                { "InitRDUnitsLoadFinishTimestampMonotonic",  "t", NULL, offsetof(BootTimes, initrd_unitsload_finish_time)  },
                { "SoftRebootsCount",                         "t", NULL, offsetof(BootTimes, soft_reboots_count)            },
                {},
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        static BootTimes times;
        static bool cached = false;
        int r;

        if (cached) {
                if (require_finished && times.finish_time <= 0)
                        return log_not_finished(times.finish_time);

                if (ret)
                        *ret = &times;
                return 0;
        }

        assert_cc(sizeof(usec_t) == sizeof(uint64_t));

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        property_map,
                        BUS_MAP_STRDUP,
                        &error,
                        NULL,
                        &times);
        if (r < 0)
                return log_error_errno(r, "Failed to get timestamp properties: %s", bus_error_message(&error, r));

        if (require_finished && times.finish_time <= 0)
                return log_not_finished(times.finish_time);

        if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM && times.soft_reboots_count > 0) {
                /* On soft-reboot ignore kernel/firmware/initrd times as they are from the previous boot */
                times.firmware_time = times.loader_time = times.kernel_time = times.initrd_time =
                                times.initrd_security_start_time = times.initrd_security_finish_time =
                                times.initrd_generators_start_time = times.initrd_generators_finish_time =
                                times.initrd_unitsload_start_time = times.initrd_unitsload_finish_time = 0;
                times.reverse_offset = times.shutdown_start_time;

                /* Clamp all timestamps to avoid showing huge graphs */
                if (timestamp_is_set(times.finish_time))
                        subtract_timestamp(&times.finish_time, times.reverse_offset);
                subtract_timestamp(&times.userspace_time, times.reverse_offset);

                subtract_timestamp(&times.generators_start_time, times.reverse_offset);
                subtract_timestamp(&times.generators_finish_time, times.reverse_offset);

                subtract_timestamp(&times.unitsload_start_time, times.reverse_offset);
                subtract_timestamp(&times.unitsload_finish_time, times.reverse_offset);
        } else if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM && timestamp_is_set(times.security_start_time)) {
                /* security_start_time is set when systemd is not running under container environment. */
                if (times.initrd_time > 0)
                        times.kernel_done_time = times.initrd_time;
                else
                        times.kernel_done_time = times.userspace_time;
        } else {
                /*
                 * User-instance-specific or container-system-specific timestamps processing
                 * (see comment to reverse_offset in BootTimes).
                 */
                times.reverse_offset = times.userspace_time;

                times.firmware_time = times.loader_time = times.kernel_time = times.initrd_time =
                        times.userspace_time = times.security_start_time = times.security_finish_time = 0;

                if (times.finish_time > 0)
                        subtract_timestamp(&times.finish_time, times.reverse_offset);

                subtract_timestamp(&times.generators_start_time, times.reverse_offset);
                subtract_timestamp(&times.generators_finish_time, times.reverse_offset);

                subtract_timestamp(&times.unitsload_start_time, times.reverse_offset);
                subtract_timestamp(&times.unitsload_finish_time, times.reverse_offset);
        }

        cached = true;

        if (ret)
                *ret = &times;
        return 0;
}

static int bus_get_uint64_property(sd_bus *bus, const char *path, const char *interface, const char *property, uint64_t *val) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(interface);
        assert(property);
        assert(val);

        r = sd_bus_get_property_trivial(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        interface,
                        property,
                        &error,
                        't', val);
        if (r < 0)
                return log_error_errno(r, "Failed to parse reply: %s", bus_error_message(&error, r));

        return 0;
}

int pretty_boot_time(sd_bus *bus, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *path = NULL, *unit_id = NULL, *text = NULL;
        usec_t activated_time = USEC_INFINITY;
        BootTimes *t;
        int r;

        r = acquire_boot_times(bus, /* require_finished = */ true, &t);
        if (r < 0)
                return r;

        path = unit_dbus_path_from_name(SPECIAL_DEFAULT_TARGET);
        if (!path)
                return log_oom();

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Id",
                        &error,
                        &unit_id);
        if (r < 0)
                log_warning_errno(r, "default.target doesn't seem to exist, ignoring: %s", bus_error_message(&error, r));

        r = bus_get_uint64_property(bus, path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveEnterTimestampMonotonic",
                        &activated_time);
        if (r < 0)
                log_warning_errno(r, "Could not get time to reach default.target, ignoring: %m");

        text = strdup("Startup finished in ");
        if (!text)
                return log_oom();

        if (timestamp_is_set(t->firmware_time) && !strextend(&text, FORMAT_TIMESPAN(t->firmware_time - t->loader_time, USEC_PER_MSEC), " (firmware) + "))
                return log_oom();
        if (timestamp_is_set(t->loader_time) && !strextend(&text, FORMAT_TIMESPAN(t->loader_time, USEC_PER_MSEC), " (loader) + "))
                return log_oom();
        if (timestamp_is_set(t->kernel_done_time) && !strextend(&text, FORMAT_TIMESPAN(t->kernel_done_time, USEC_PER_MSEC), " (kernel) + "))
                return log_oom();
        if (timestamp_is_set(t->initrd_time) && !strextend(&text, FORMAT_TIMESPAN(t->userspace_time - t->initrd_time, USEC_PER_MSEC), " (initrd) + "))
                return log_oom();
        if (t->soft_reboots_count > 0 && strextendf(&text, "%s (soft reboot #%" PRIu64 ") + ", FORMAT_TIMESPAN(t->userspace_time, USEC_PER_MSEC), t->soft_reboots_count) < 0)
                return log_oom();

        if (!strextend(&text, FORMAT_TIMESPAN(t->finish_time - t->userspace_time, USEC_PER_MSEC), " (userspace) "))
                return log_oom();

        if (timestamp_is_set(t->kernel_done_time))
                if (!strextend(&text, "= ", FORMAT_TIMESPAN(t->firmware_time + t->finish_time, USEC_PER_MSEC),  " "))
                        return log_oom();

        if (unit_id && timestamp_is_set(activated_time)) {
                usec_t base;

                /* On soft-reboot times are clamped to avoid showing huge graphs */
                if (t->soft_reboots_count > 0 && timestamp_is_set(t->userspace_time))
                        base = t->userspace_time + t->reverse_offset;
                else
                        base = timestamp_is_set(t->userspace_time) ? t->userspace_time : t->reverse_offset;

                if (!strextend(&text, "\n", unit_id, " reached after ", FORMAT_TIMESPAN(activated_time - base, USEC_PER_MSEC), " in userspace."))
                        return log_oom();

        } else if (unit_id && activated_time == 0) {

                if (!strextend(&text, "\n", unit_id, " was never reached."))
                        return log_oom();

        } else if (unit_id && activated_time == USEC_INFINITY) {

                if (!strextend(&text, "\nCould not get time to reach ", unit_id, "."))
                        return log_oom();

        } else if (!unit_id) {

                if (!strextend(&text, "\ncould not find default.target."))
                        return log_oom();
        }

        *ret = TAKE_PTR(text);
        return 0;
}

void unit_times_clear(UnitTimes *t) {
        if (!t)
                return;

        FOREACH_ELEMENT(d, t->deps)
                *d = strv_free(*d);

        t->name = mfree(t->name);
}

UnitTimes* unit_times_free_array(UnitTimes *t) {
        if (!t)
                return NULL;

        for (UnitTimes *p = t; p->has_data; p++)
                unit_times_clear(p);

        return mfree(t);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(UnitTimes*, unit_times_clear, NULL);

int acquire_time_data(sd_bus *bus, bool require_finished, UnitTimes **out) {
        static const struct bus_properties_map property_map[] = {
                { "InactiveExitTimestampMonotonic",  "t",  NULL, offsetof(UnitTimes, activating)           },
                { "ActiveEnterTimestampMonotonic",   "t",  NULL, offsetof(UnitTimes, activated)            },
                { "ActiveExitTimestampMonotonic",    "t",  NULL, offsetof(UnitTimes, deactivating)         },
                { "InactiveEnterTimestampMonotonic", "t",  NULL, offsetof(UnitTimes, deactivated)          },
                { "After",                           "as", NULL, offsetof(UnitTimes, deps[UNIT_AFTER])     },
                { "Before",                          "as", NULL, offsetof(UnitTimes, deps[UNIT_BEFORE])    },
                { "Requires",                        "as", NULL, offsetof(UnitTimes, deps[UNIT_REQUIRES])  },
                { "Requisite",                       "as", NULL, offsetof(UnitTimes, deps[UNIT_REQUISITE]) },
                { "Wants",                           "as", NULL, offsetof(UnitTimes, deps[UNIT_WANTS])     },
                { "Conflicts",                       "as", NULL, offsetof(UnitTimes, deps[UNIT_CONFLICTS]) },
                { "Upholds",                         "as", NULL, offsetof(UnitTimes, deps[UNIT_UPHOLDS])   },
                {},
        };
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *unit_times = NULL;
        BootTimes *boot_times;
        size_t c = 0;
        UnitInfo u;
        int r;

        r = acquire_boot_times(bus, require_finished, &boot_times);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "ListUnits", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {
                _cleanup_(unit_times_clearp) UnitTimes *t = NULL;

                if (!GREEDY_REALLOC0(unit_times, c + 2))
                        return log_oom();

                /* t initially has pointers zeroed by the allocation, and unit_times_clearp will have zeroed
                 * them if the entry is being reused. */
                t = &unit_times[c];

                assert_cc(sizeof(usec_t) == sizeof(uint64_t));

                r = bus_map_all_properties(
                                bus,
                                "org.freedesktop.systemd1",
                                u.unit_path,
                                property_map,
                                BUS_MAP_STRDUP,
                                &error,
                                NULL,
                                t);
                if (r < 0)
                        return log_error_errno(r, "Failed to get timestamp properties of unit %s: %s",
                                               u.id, bus_error_message(&error, r));

                /* Activated in the previous soft-reboot iteration? Ignore it, we want new activations */
                if ((t->activated > 0 && t->activated < boot_times->shutdown_start_time) ||
                    (t->activating > 0 && t->activating < boot_times->shutdown_start_time))
                        continue;

                subtract_timestamp(&t->activating, boot_times->reverse_offset);
                subtract_timestamp(&t->activated, boot_times->reverse_offset);

                /* If the last deactivation was in the previous soft-reboot, ignore it */
                if (boot_times->soft_reboots_count > 0) {
                        if (t->deactivating < boot_times->reverse_offset)
                                t->deactivating = 0;
                        else
                                subtract_timestamp(&t->deactivating, boot_times->reverse_offset);
                        if (t->deactivated < boot_times->reverse_offset)
                                t->deactivated = 0;
                        else
                                subtract_timestamp(&t->deactivated, boot_times->reverse_offset);
                } else {
                        subtract_timestamp(&t->deactivating, boot_times->reverse_offset);
                        subtract_timestamp(&t->deactivated, boot_times->reverse_offset);
                }

                if (t->activated >= t->activating)
                        t->time = t->activated - t->activating;
                else if (t->deactivated >= t->activating)
                        t->time = t->deactivated - t->activating;
                else
                        t->time = 0;

                if (t->activating == 0)
                        continue;

                t->name = strdup(u.id);
                if (!t->name)
                        return log_oom();

                t->has_data = true;
                /* Prevent destructor from running on t reference. */
                TAKE_PTR(t);
                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        *out = TAKE_PTR(unit_times);
        return c;
}
