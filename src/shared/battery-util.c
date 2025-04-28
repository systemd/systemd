/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "battery-util.h"
#include "device-private.h"
#include "device-util.h"
#include "string-util.h"

#define BATTERY_LOW_CAPACITY_LEVEL 5

static int device_is_power_sink(sd_device *device) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool found_source = false, found_sink = false;
        sd_device *parent;
        int r;

        assert(device);

        /* USB-C power supply device has two power roles: source or sink. See,
         * https://docs.kernel.org/admin-guide/abi-testing.html#abi-file-testing-sysfs-class-typec */

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "typec", true);
        if (r < 0)
                return r;

        r = sd_device_get_parent(device, &parent);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_parent(e, parent);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                const char *val;

                r = sd_device_get_sysattr_value(d, "power_role", &val);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_device_debug_errno(d, r, "Failed to read 'power_role' sysfs attribute, ignoring: %m");
                        continue;
                }

                if (strstr(val, "[source]")) {
                        found_source = true;
                        log_device_debug(d, "The USB type-C port is in power source mode.");
                } else if (strstr(val, "[sink]")) {
                        found_sink = true;
                        log_device_debug(d, "The USB type-C port is in power sink mode.");
                }
        }

        if (found_sink)
                log_device_debug(device, "The USB type-C device has at least one port in power sink mode.");
        else if (!found_source)
                log_device_debug(device, "The USB type-C device has no port in power source mode, assuming the device is in power sink mode.");
        else
                log_device_debug(device, "All USB type-C ports are in power source mode.");

        return found_sink || !found_source;
}

static bool battery_is_discharging(sd_device *d) {
        const char *val;
        int r;

        assert(d);

        r = sd_device_get_sysattr_value(d, "scope", &val);
        if (r < 0) {
                if (r != -ENOENT)
                        log_device_debug_errno(d, r, "Failed to read 'scope' sysfs attribute, ignoring: %m");
        } else if (streq(val, "Device")) {
                log_device_debug(d, "The power supply is a device battery, ignoring device.");
                return false;
        }

        r = device_get_sysattr_bool(d, "present");
        if (r < 0)
                log_device_debug_errno(d, r, "Failed to read 'present' sysfs attribute, assuming the battery is present: %m");
        else if (r == 0) {
                log_device_debug(d, "The battery is not present, ignoring the power supply.");
                return false;
        }

        /* Possible values: "Unknown", "Charging", "Discharging", "Not charging", "Full" */
        r = sd_device_get_sysattr_value(d, "status", &val);
        if (r < 0) {
                log_device_debug_errno(d, r, "Failed to read 'status' sysfs attribute, assuming the battery is discharging: %m");
                return true;
        }
        if (!streq(val, "Discharging")) {
                log_device_debug(d, "The battery status is '%s', assuming the battery is not used as a power source of this machine.", val);
                return false;
        }

        return true;
}

int on_ac_power(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool found_ac_online = false, found_discharging_battery = false;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "power_supply", true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                /* See
                 * https://github.com/torvalds/linux/blob/4eef766b7d4d88f0b984781bc1bcb574a6eafdc7/include/linux/power_supply.h#L176
                 * for defined power source types. Also see:
                 * https://docs.kernel.org/admin-guide/abi-testing.html#abi-file-testing-sysfs-class-power */

                const char *val;
                r = sd_device_get_sysattr_value(d, "type", &val);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to read 'type' sysfs attribute, ignoring device: %m");
                        continue;
                }

                /* Ignore USB-C power supply in source mode. See issue #21988. */
                if (streq(val, "USB")) {
                        r = device_is_power_sink(d);
                        if (r <= 0) {
                                if (r < 0)
                                        log_device_debug_errno(d, r, "Failed to determine the current power role, ignoring device: %m");
                                else
                                        log_device_debug(d, "USB power supply is in source mode, ignoring device.");
                                continue;
                        }
                }

                if (streq(val, "Battery")) {
                        if (battery_is_discharging(d)) {
                                found_discharging_battery = true;
                                log_device_debug(d, "The power supply is a battery and currently discharging.");
                        }
                        continue;
                }

                r = device_get_sysattr_unsigned(d, "online", NULL);
                if (r < 0) {
                        log_device_debug_errno(d, r, "Failed to query 'online' sysfs attribute, ignoring device: %m");
                        continue;
                } else if (r > 0)  /* At least 1 and 2 are defined as different types of 'online' */
                        found_ac_online = true;

                log_device_debug(d, "The power supply is currently %s.", r > 0 ? "online" : "offline");
        }

        if (found_ac_online) {
                log_debug("Found at least one online non-battery power supply, system is running on AC.");
                return true;
        } else if (found_discharging_battery) {
                log_debug("Found at least one discharging battery and no online power sources, assuming system is running from battery.");
                return false;
        } else {
                log_debug("No power supply reported online and no discharging battery found, assuming system is running on AC.");
                return true;
        }
}

/* Get the list of batteries */
int battery_enumerator_new(sd_device_enumerator **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(ret);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "power_supply", /* match = */ true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "type", "Battery", /* match = */ true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "present", "1", /* match = */ true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "scope", "Device", /* match = */ false);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(e);
        return 0;
}

/* Battery percentage capacity fetched from capacity file and if in range 0-100 then returned */
int battery_read_capacity_percentage(sd_device *dev) {
        int battery_capacity, r;

        assert(dev);

        r = device_get_sysattr_int(dev, "capacity", &battery_capacity);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read/parse POWER_SUPPLY_CAPACITY: %m");

        if (battery_capacity < 0 || battery_capacity > 100)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ERANGE), "Invalid battery capacity: %d", battery_capacity);

        return battery_capacity;
}

/* If a battery whose percentage capacity is <= 5% exists, and we're not on AC power, return success */
int battery_is_discharging_and_low(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool unsure = false, found_low = false;
        int r;

         /* We have not used battery capacity_level since value is set to full
         * or Normal in case ACPI is not working properly. In case of no battery
         * 0 will be returned and system will be suspended for 1st cycle then hibernated */

        r = on_ac_power();
        if (r < 0)
                log_warning_errno(r, "Failed to check if the system is running on AC, assuming it is not: %m");
        if (r > 0)
                return false;

        r = battery_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize battery enumerator: %m");

        FOREACH_DEVICE(e, dev) {
                int level;

                level = battery_read_capacity_percentage(dev);
                if (level < 0) {
                        unsure = true;
                        continue;
                }

                if (level > BATTERY_LOW_CAPACITY_LEVEL) { /* Found a charged battery */
                        log_device_full(dev,
                                        found_low ? LOG_INFO : LOG_DEBUG,
                                        "Found battery with capacity above threshold (%d%% > %d%%).",
                                        level, BATTERY_LOW_CAPACITY_LEVEL);
                        return false;
                }

                log_device_info(dev,
                                "Found battery with capacity below threshold (%d%% <= %d%%).",
                                level, BATTERY_LOW_CAPACITY_LEVEL);
                found_low = true;
        }

        /* If we found a battery whose state we couldn't read, don't assume we are in low battery state */
        if (unsure) {
                log_notice("Found battery with unreadable state, assuming not in low battery state.");
                return false;
        }

        /* If found neither charged nor low batteries, assume that we aren't in low battery state */
        return found_low;
}
