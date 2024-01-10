/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "battery-capacity.h"
#include "battery-util.h"
#include "device-private.h"
#include "device-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "parse-util.h"
#include "siphash24.h"

#define DISCHARGE_RATE_FILEPATH "/var/lib/systemd/sleep/battery_discharge_percentage_rate_per_hour"
#define BATTERY_DISCHARGE_RATE_HASH_KEY SD_ID128_MAKE(5f,9a,20,18,38,76,46,07,8d,36,58,0b,bb,c4,e0,63)

static void *CAPACITY_TO_PTR(int capacity) {
        assert(capacity >= 0);
        assert(capacity <= 100);
        return INT_TO_PTR(capacity + 1);
}

static int PTR_TO_CAPACITY(void *p) {
        int capacity = PTR_TO_INT(p) - 1;
        assert(capacity >= 0);
        assert(capacity <= 100);
        return capacity;
}

static int siphash24_compress_device_sysattr(
                sd_device *dev,
                const char *attr,
                struct siphash *state) {

        const char *x;
        int r;

        assert(dev);
        assert(attr);
        assert(state);

        r = sd_device_get_sysattr_value(dev, attr, &x);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to read '%s' attribute: %m", attr);

        if (!isempty(x))
                siphash24_compress_string(x, state);

        return 0;
}

static int siphash24_compress_id128(
                int (*getter)(sd_id128_t *ret),
                const char *name,
                struct siphash *state) {

        sd_id128_t id;
        int r;

        assert(getter);
        assert(name);
        assert(state);

        r = getter(&id);
        if (r < 0)
                return log_debug_errno(r, "Failed to get %s ID: %m", name);

        siphash24_compress_typesafe(id, state);
        return 0;
}

/* Read system and battery identifier from specific location and generate hash of it */
static uint64_t system_battery_identifier_hash(sd_device *dev) {
        struct siphash state;

        assert(dev);

        siphash24_init(&state, BATTERY_DISCHARGE_RATE_HASH_KEY.bytes);

        (void) siphash24_compress_device_sysattr(dev, "manufacturer", &state);
        (void) siphash24_compress_device_sysattr(dev, "model_name", &state);
        (void) siphash24_compress_device_sysattr(dev, "serial_number", &state);
        (void) siphash24_compress_id128(sd_id128_get_machine, "machine", &state);
        (void) siphash24_compress_id128(id128_get_product, "product", &state);

        return siphash24_finalize(&state);
}

/* Return success if battery percentage discharge rate per hour is in the range 1–199 */
static bool battery_discharge_rate_is_valid(int battery_discharge_rate) {
        return battery_discharge_rate > 0 && battery_discharge_rate < 200;
}

/* Battery percentage discharge rate per hour is read from specific file. It is stored along with system
 * and battery identifier hash to maintain the integrity of discharge rate value */
static int get_battery_discharge_rate(sd_device *dev, int *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        uint64_t current_hash_id;
        const char *p;
        int r;

        assert(dev);
        assert(ret);

        f = fopen(DISCHARGE_RATE_FILEPATH, "re");
        if (!f)
                return log_debug_errno(errno, "Failed to read discharge rate from " DISCHARGE_RATE_FILEPATH ": %m");

        current_hash_id = system_battery_identifier_hash(dev);

        for (;;) {
                _cleanup_free_ char *stored_hash_id = NULL, *stored_discharge_rate = NULL, *line = NULL;
                uint64_t hash_id;
                int discharge_rate;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read discharge rate from " DISCHARGE_RATE_FILEPATH ": %m");
                if (r == 0)
                        break;

                p = line;
                r = extract_many_words(&p, NULL, 0, &stored_hash_id, &stored_discharge_rate, NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse hash_id and discharge_rate read from " DISCHARGE_RATE_FILEPATH ": %m");
                if (r != 2)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid number of items fetched from " DISCHARGE_RATE_FILEPATH);

                r = safe_atou64(stored_hash_id, &hash_id);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse hash ID read from " DISCHARGE_RATE_FILEPATH " location: %m");

                if (current_hash_id != hash_id)
                        /* matching device not found, move to next line */
                        continue;

                r = safe_atoi(stored_discharge_rate, &discharge_rate);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to parse discharge rate read from " DISCHARGE_RATE_FILEPATH ": %m");

                if (!battery_discharge_rate_is_valid(discharge_rate))
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(ERANGE), "Invalid battery discharge percentage rate per hour: %m");

                *ret = discharge_rate;
                return 0; /* matching device found, exit iteration */
        }

        return -ENOENT;
}

/* Write battery percentage discharge rate per hour along with system and battery identifier hash to file */
static int put_battery_discharge_rate(int estimated_battery_discharge_rate, uint64_t system_hash_id, bool trunc) {
        int r;

        if (!battery_discharge_rate_is_valid(estimated_battery_discharge_rate))
                return log_debug_errno(SYNTHETIC_ERRNO(ERANGE),
                                        "Invalid battery discharge rate %d%% per hour: %m",
                                        estimated_battery_discharge_rate);

        r = write_string_filef(
                        DISCHARGE_RATE_FILEPATH,
                        WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_MKDIR_0755 | (trunc ? WRITE_STRING_FILE_TRUNCATE : 0),
                        "%"PRIu64" %d",
                        system_hash_id,
                        estimated_battery_discharge_rate);
        if (r < 0)
                return log_debug_errno(r, "Failed to update %s: %m", DISCHARGE_RATE_FILEPATH);

        log_debug("Estimated discharge rate %d%% per hour successfully saved to %s", estimated_battery_discharge_rate, DISCHARGE_RATE_FILEPATH);

        return 0;
}

/* Store current capacity of each battery before suspension and timestamp */
int fetch_batteries_capacity_by_name(Hashmap **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_hashmap_free_ Hashmap *batteries_capacity_by_name = NULL;
        int r;

        assert(ret);

        batteries_capacity_by_name = hashmap_new(&string_hash_ops_free);
        if (!batteries_capacity_by_name)
                return log_oom_debug();

        r = battery_enumerator_new(&e);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize battery enumerator: %m");

        FOREACH_DEVICE(e, dev) {
                _cleanup_free_ char *battery_name_copy = NULL;
                const char *battery_name;
                int battery_capacity;

                battery_capacity = r = battery_read_capacity_percentage(dev);
                if (r < 0)
                        continue;

                r = sd_device_get_property_value(dev, "POWER_SUPPLY_NAME", &battery_name);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to get POWER_SUPPLY_NAME property, ignoring: %m");
                        continue;
                }

                battery_name_copy = strdup(battery_name);
                if (!battery_name_copy)
                        return log_oom_debug();

                r = hashmap_put(batteries_capacity_by_name, battery_name_copy, CAPACITY_TO_PTR(battery_capacity));
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to store battery capacity: %m");

                TAKE_PTR(battery_name_copy);
        }

        *ret = TAKE_PTR(batteries_capacity_by_name);

        return 0;
}

int get_capacity_by_name(Hashmap *capacities_by_name, const char *name) {
        void *p;

        assert(capacities_by_name);
        assert(name);

        p = hashmap_get(capacities_by_name, name);
        if (!p)
                return -ENOENT;

        return PTR_TO_CAPACITY(p);
}

/* Estimate battery discharge rate using stored previous and current capacity over timestamp difference */
int estimate_battery_discharge_rate_per_hour(
                Hashmap *last_capacity,
                Hashmap *current_capacity,
                usec_t before_timestamp,
                usec_t after_timestamp) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool trunc = true;
        int r;

        assert(last_capacity);
        assert(current_capacity);
        assert(before_timestamp < after_timestamp);

        r = battery_enumerator_new(&e);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize battery enumerator: %m");

        FOREACH_DEVICE(e, dev) {
                int battery_last_capacity, battery_current_capacity, battery_discharge_rate;
                const char *battery_name;
                uint64_t system_hash_id;

                r = sd_device_get_property_value(dev, "POWER_SUPPLY_NAME", &battery_name);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to read battery name, ignoring: %m");
                        continue;
                }

                battery_last_capacity = get_capacity_by_name(last_capacity, battery_name);
                if (battery_last_capacity < 0)
                        continue;

                battery_current_capacity = get_capacity_by_name(current_capacity, battery_name);
                if (battery_current_capacity < 0)
                        continue;

                if (battery_current_capacity >= battery_last_capacity) {
                        log_device_debug(dev, "Battery was not discharged during suspension");
                        continue;
                }

                system_hash_id = system_battery_identifier_hash(dev);

                log_device_debug(dev,
                                 "%d%% was discharged in %s. Estimating discharge rate...",
                                 battery_last_capacity - battery_current_capacity,
                                 FORMAT_TIMESPAN(after_timestamp - before_timestamp, USEC_PER_SEC));

                battery_discharge_rate = (battery_last_capacity - battery_current_capacity) * USEC_PER_HOUR / (after_timestamp - before_timestamp);
                r = put_battery_discharge_rate(battery_discharge_rate, system_hash_id, trunc);
                if (r < 0)
                        log_device_warning_errno(dev, r, "Failed to update battery discharge rate, ignoring: %m");
                else
                        trunc = false;
        }

        return 0;
}

/* Calculate the suspend interval for each battery and then return their sum */
int get_total_suspend_interval(Hashmap *last_capacity, usec_t *ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        usec_t total_suspend_interval = 0;
        int r;

        assert(last_capacity);
        assert(ret);

        r = battery_enumerator_new(&e);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize battery enumerator: %m");

        FOREACH_DEVICE(e, dev) {
                int battery_last_capacity, previous_discharge_rate = 0;
                const char *battery_name;
                usec_t suspend_interval;

                r = sd_device_get_property_value(dev, "POWER_SUPPLY_NAME", &battery_name);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to read battery name, ignoring: %m");
                        continue;
                }

                battery_last_capacity = get_capacity_by_name(last_capacity, battery_name);
                if (battery_last_capacity <= 0)
                        continue;

                r = get_battery_discharge_rate(dev, &previous_discharge_rate);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to get discharge rate, ignoring: %m");
                        continue;
                }

                if (previous_discharge_rate == 0)
                        continue;

                if (battery_last_capacity * 2 <= previous_discharge_rate) {
                        log_device_debug(dev, "Current battery capacity percentage too low compared to discharge rate");
                        continue;
                }
                suspend_interval = battery_last_capacity * USEC_PER_HOUR / previous_discharge_rate;

                total_suspend_interval = usec_add(total_suspend_interval, suspend_interval);
        }
        /* Previous discharge rate is stored in per hour basis converted to usec.
         * Subtract 30 minutes from the result to keep a buffer of 30 minutes before battery gets critical */
        total_suspend_interval = usec_sub_unsigned(total_suspend_interval, 30 * USEC_PER_MINUTE);
        if (total_suspend_interval == 0)
                return -ENOENT;

        *ret = total_suspend_interval;

        return 0;
}

/* Return true if all batteries have acpi_btp support */
int battery_trip_point_alarm_exists(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        bool has_battery = false;
        int r;

        r = battery_enumerator_new(&e);
        if (r < 0)
                return log_debug_errno(r, "Failed to initialize battery enumerator: %m");

        FOREACH_DEVICE(e, dev) {
                const char *alarm_attr;
                int has_alarm;

                has_battery = true;

                r = sd_device_get_sysattr_value(dev, "alarm", &alarm_attr);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to read battery alarm attribute: %m");

                r = safe_atoi(alarm_attr, &has_alarm);
                if (r < 0)
                        return log_device_debug_errno(dev, r,
                                                      "Failed to parse battery alarm attribute '%s': %m",
                                                      alarm_attr);
                if (has_alarm <= 0)
                        return false;
        }

        return has_battery;
}
