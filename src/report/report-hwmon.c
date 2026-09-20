/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "device-private.h"
#include "device-util.h"
#include "json-util.h"
#include "log.h"
#include "metrics.h"
#include "parse-util.h"
#include "report-hwmon.h"
#include "sort-util.h"
#include "string-util.h"

/* The kernel's hwmon sysfs interface (see https://docs.kernel.org/hwmon/sysfs-interface.html) exposes
 * temperature sensors as temp<N>_input attributes, in millidegrees Celsius. Only the current reading is
 * reported here. The various limits (temp<N>_min, temp<N>_max, temp<N>_crit, …) and alarm flags are static
 * configuration rather than measurements, and hence deliberately not reported as metrics. */

static int parse_temperature_index(const char *attr, unsigned *ret) {
        const char *e;
        unsigned n;
        int r;

        assert(attr);
        assert(ret);

        e = startswith(attr, "temp");
        if (!e)
                return 0;

        const char *u = endswith(e, "_input");
        if (!u)
                return 0;

        _cleanup_free_ char *idx = strndup(e, u - e);
        if (!idx)
                return -ENOMEM;

        r = safe_atou_full(idx, SAFE_ATO_REFUSE_PLUS_MINUS|SAFE_ATO_REFUSE_LEADING_ZERO|SAFE_ATO_REFUSE_LEADING_WHITESPACE, &n);
        if (r < 0)
                return 0;

        *ret = n;
        return 1;
}

static int hwmon_temperature_sensor_send(
                const MetricFamily *mf,
                sd_varlink *link,
                sd_device *device,
                const char *object,
                const char *chip,
                unsigned index) {

        int r;

        assert(mf);
        assert(link);
        assert(device);
        assert(object);

        _cleanup_free_ char *sensor = NULL;
        if (asprintf(&sensor, "temp%u", index) < 0)
                return log_oom();

        /* A faulted sensor may still return a (garbage) reading, hence check the fault flag explicitly. Most
         * drivers do not expose the flag at all, in which case we assume all is fine. */
        _cleanup_free_ char *fault_attr = strjoin(sensor, "_fault");
        if (!fault_attr)
                return log_oom();

        r = device_get_sysattr_bool(device, fault_attr);
        if (r > 0) {
                log_device_debug(device, "Sensor %s reports a fault, skipping.", sensor);
                return 0;
        }

        _cleanup_free_ char *input_attr = strjoin(sensor, "_input");
        if (!input_attr)
                return log_oom();

        /* Drivers return a variety of errors for sensors that are absent, disabled or temporarily not
         * readable (-ENODATA, -ENODEV, -EIO, -EAGAIN, …). None of these are worth more than a debug message:
         * a sensor we cannot read simply produces no data point. */
        int millidegrees;
        r = device_get_sysattr_int(device, input_attr, &millidegrees);
        if (r < 0) {
                log_device_debug_errno(device, r, "Failed to read sensor %s, ignoring: %m", sensor);
                return 0;
        }

        _cleanup_free_ char *label_attr = strjoin(sensor, "_label");
        if (!label_attr)
                return log_oom();

        const char *label = NULL;
        r = device_get_sysattr_safe_string(device, label_attr, &label);
        if (r < 0 && r != -ENOENT)
                log_device_debug_errno(device, r, "Failed to read label of sensor %s, ignoring: %m", sensor);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fields = NULL;
        r = sd_json_buildo(
                        &fields,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("chip", chip),
                        SD_JSON_BUILD_PAIR_STRING("sensor", sensor),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("label", label));
        if (r < 0)
                return log_error_errno(r, "Failed to build metric fields: %m");

        return metric_build_send_double(mf, link, object, (double) millidegrees / 1000, fields);
}

static int hwmon_device_send(const MetricFamily *mf, sd_varlink *link, sd_device *device) {
        int r;

        assert(mf);
        assert(link);
        assert(device);

        /* Collect the sensor indices first, and sort them: the sysattr enumeration order is not stable, but
         * we want deterministic output. Indices are sparse (coretemp for example numbers sensors by core ID),
         * hence scanning the attribute list beats probing temp1…tempN. */
        _cleanup_free_ unsigned *indices = NULL;
        size_t n_indices = 0;

        FOREACH_DEVICE_SYSATTR(device, attr) {
                unsigned n;

                r = parse_temperature_index(attr, &n);
                if (r < 0)
                        return log_oom();
                if (r == 0)
                        continue;

                if (!GREEDY_REALLOC(indices, n_indices + 1))
                        return log_oom();

                indices[n_indices++] = n;
        }

        if (n_indices == 0)
                return 0;

        typesafe_qsort(indices, n_indices, cmp_unsigned);

        /* Identify the sensor by the device the hwmon chip belongs to (e.g. "coretemp.0", "nvme0",
         * "thermal_zone0"), as the hwmon<N> names are assigned in probe order and hence not stable across
         * boots, while the chip name (e.g. "nvme") is not unique. */
        const char *object;
        sd_device *parent;
        r = sd_device_get_parent(device, &parent);
        if (r >= 0)
                r = sd_device_get_sysname(parent, &object);
        if (r < 0) {
                r = sd_device_get_sysname(device, &object);
                if (r < 0)
                        return log_device_debug_errno(device, r, "Failed to get hwmon device name: %m");
        }

        const char *chip = NULL;
        r = device_get_sysattr_safe_string(device, "name", &chip);
        if (r < 0)
                log_device_debug_errno(device, r, "Failed to read hwmon chip name, ignoring: %m");

        FOREACH_ARRAY(i, indices, n_indices) {
                r = hwmon_temperature_sensor_send(mf, link, device, object, chip, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int hwmon_temperature_generate(const MetricFamily *mf, sd_varlink *link, void *userdata) {
        int r;

        assert(mf && mf->name);
        assert(link);

        /* Note that a fresh enumerator (and hence fresh sd_device objects) is used for each call, so that
         * the sysattr cache in sd-device never hands out stale readings. */
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate device enumerator: %m");

        r = sd_device_enumerator_add_match_subsystem(e, "hwmon", /* match= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add hwmon subsystem match to enumerator: %m");

        (void) sd_device_enumerator_allow_uninitialized(e);

        FOREACH_DEVICE(e, device) {
                r = hwmon_device_send(mf, link, device);
                if (r < 0)
                        return r;
        }

        return 0;
}

static const MetricFamily hwmon_metric_family_table[] = {
        /* Keep metrics ordered alphabetically */
        {
                "io.systemd.HWMon.TemperatureCelsius",
                "Per hwmon sensor metric: current temperature in degrees Celsius "
                "(object=parent device, chip=hwmon chip name, sensor=temp<N>, label=sensor label if any)",
                METRIC_FAMILY_TYPE_GAUGE,
                .generate = hwmon_temperature_generate,
        },
        {}
};

int vl_method_describe_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_describe(hwmon_metric_family_table, link, parameters, flags, userdata);
}

int vl_method_list_metrics(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return metrics_method_list(hwmon_metric_family_table, link, parameters, flags, userdata);
}
