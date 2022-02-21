/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-time-data.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"

static void subtract_timestamp(usec_t *a, usec_t b) {
        assert(a);

        if (*a > 0) {
                assert(*a >= b);
                *a -= b;
        }
}

int acquire_boot_times(sd_bus *bus, BootTimes **ret) {
        static const struct bus_properties_map property_map[] = {
                { "FirmwareTimestampMonotonic",               "t", NULL, offsetof(BootTimes, firmware_time)                 },
                { "LoaderTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, loader_time)                   },
                { "KernelTimestamp",                          "t", NULL, offsetof(BootTimes, kernel_time)                   },
                { "InitRDTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, initrd_time)                   },
                { "UserspaceTimestampMonotonic",              "t", NULL, offsetof(BootTimes, userspace_time)                },
                { "FinishTimestampMonotonic",                 "t", NULL, offsetof(BootTimes, finish_time)                   },
                { "SecurityStartTimestampMonotonic",          "t", NULL, offsetof(BootTimes, security_start_time)           },
                { "SecurityFinishTimestampMonotonic",         "t", NULL, offsetof(BootTimes, security_finish_time)          },
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
                {},
        };
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        static BootTimes times;
        static bool cached = false;
        int r;

        if (cached)
                goto finish;

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

        if (times.finish_time <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINPROGRESS),
                                       "Bootup is not yet finished (org.freedesktop.systemd1.Manager.FinishTimestampMonotonic=%"PRIu64").\n"
                                       "Please try again later.\n"
                                       "Hint: Use 'systemctl%s list-jobs' to see active jobs",
                                       times.finish_time,
                                       arg_scope == UNIT_FILE_SYSTEM ? "" : " --user");

        if (arg_scope == UNIT_FILE_SYSTEM && times.security_start_time > 0) {
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

                subtract_timestamp(&times.finish_time, times.reverse_offset);

                subtract_timestamp(&times.generators_start_time, times.reverse_offset);
                subtract_timestamp(&times.generators_finish_time, times.reverse_offset);

                subtract_timestamp(&times.unitsload_start_time, times.reverse_offset);
                subtract_timestamp(&times.unitsload_finish_time, times.reverse_offset);
        }

        cached = true;

finish:
        *ret = &times;
        return 0;
}

UnitTimes* unit_times_free_array(UnitTimes *t) {
        if (!t)
                return NULL;

        for (UnitTimes *p = t; p->has_data; p++)
                free(p->name);

        return mfree(t);
}

int acquire_time_data(sd_bus *bus, UnitTimes **out) {
        static const struct bus_properties_map property_map[] = {
                { "InactiveExitTimestampMonotonic",  "t", NULL, offsetof(UnitTimes, activating)   },
                { "ActiveEnterTimestampMonotonic",   "t", NULL, offsetof(UnitTimes, activated)    },
                { "ActiveExitTimestampMonotonic",    "t", NULL, offsetof(UnitTimes, deactivating) },
                { "InactiveEnterTimestampMonotonic", "t", NULL, offsetof(UnitTimes, deactivated)  },
                {},
        };
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *unit_times = NULL;
        BootTimes *boot_times = NULL;
        size_t c = 0;
        UnitInfo u;
        int r;

        r = acquire_boot_times(bus, &boot_times);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "ListUnits", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list units: %s", bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = bus_parse_unit_info(reply, &u)) > 0) {
                UnitTimes *t;

                if (!GREEDY_REALLOC(unit_times, c + 2))
                        return log_oom();

                unit_times[c + 1].has_data = false;
                t = &unit_times[c];
                t->name = NULL;

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

                subtract_timestamp(&t->activating, boot_times->reverse_offset);
                subtract_timestamp(&t->activated, boot_times->reverse_offset);
                subtract_timestamp(&t->deactivating, boot_times->reverse_offset);
                subtract_timestamp(&t->deactivated, boot_times->reverse_offset);

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
                c++;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        *out = TAKE_PTR(unit_times);
        return c;
}
