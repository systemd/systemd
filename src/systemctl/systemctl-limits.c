/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "bus-error.h"
#include "bus-map-properties.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "format-table.h"
#include "format-util.h"
#include "log.h"
#include "pager.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-limits.h"
#include "systemctl-util.h"
#include "time-util.h"
#include "unit-def.h"

typedef struct UnitLimitsInfo {
        const char *load_state;

        /* CPU */
        uint64_t cpu_weight;
        uint64_t startup_cpu_weight;
        uint64_t cpu_quota_per_sec_usec;
        uint64_t cpu_quota_period_usec;

        /* Memory */
        uint64_t memory_min;
        uint64_t memory_low;
        uint64_t startup_memory_low;
        uint64_t memory_high;
        uint64_t startup_memory_high;
        uint64_t memory_max;
        uint64_t startup_memory_max;
        uint64_t memory_swap_max;
        uint64_t startup_memory_swap_max;
        uint64_t memory_zswap_max;
        uint64_t startup_memory_zswap_max;

        /* Tasks */
        uint64_t tasks_max;

        /* IO */
        uint64_t io_weight;
        uint64_t startup_io_weight;

        /* Effective limits (from parent slices) */
        uint64_t effective_memory_high;
        uint64_t effective_memory_max;
        uint64_t effective_tasks_max;

        /* Current usage */
        uint64_t memory_current;
        uint64_t memory_swap_current;
        uint64_t memory_zswap_current;
        uint64_t tasks_current;
} UnitLimitsInfo;

static const struct bus_properties_map limits_map[] = {
        { "LoadState",              "s", NULL, offsetof(UnitLimitsInfo, load_state)              },

        /* CPU */
        { "CPUWeight",              "t", NULL, offsetof(UnitLimitsInfo, cpu_weight)               },
        { "StartupCPUWeight",       "t", NULL, offsetof(UnitLimitsInfo, startup_cpu_weight)       },
        { "CPUQuotaPerSecUSec",     "t", NULL, offsetof(UnitLimitsInfo, cpu_quota_per_sec_usec)   },
        { "CPUQuotaPeriodUSec",     "t", NULL, offsetof(UnitLimitsInfo, cpu_quota_period_usec)    },

        /* Memory */
        { "MemoryMin",              "t", NULL, offsetof(UnitLimitsInfo, memory_min)               },
        { "MemoryLow",              "t", NULL, offsetof(UnitLimitsInfo, memory_low)               },
        { "StartupMemoryLow",       "t", NULL, offsetof(UnitLimitsInfo, startup_memory_low)       },
        { "MemoryHigh",             "t", NULL, offsetof(UnitLimitsInfo, memory_high)              },
        { "StartupMemoryHigh",      "t", NULL, offsetof(UnitLimitsInfo, startup_memory_high)      },
        { "MemoryMax",              "t", NULL, offsetof(UnitLimitsInfo, memory_max)               },
        { "StartupMemoryMax",       "t", NULL, offsetof(UnitLimitsInfo, startup_memory_max)       },
        { "MemorySwapMax",          "t", NULL, offsetof(UnitLimitsInfo, memory_swap_max)          },
        { "StartupMemorySwapMax",   "t", NULL, offsetof(UnitLimitsInfo, startup_memory_swap_max)  },
        { "MemoryZSwapMax",         "t", NULL, offsetof(UnitLimitsInfo, memory_zswap_max)         },
        { "StartupMemoryZSwapMax",  "t", NULL, offsetof(UnitLimitsInfo, startup_memory_zswap_max) },

        /* Tasks */
        { "TasksMax",               "t", NULL, offsetof(UnitLimitsInfo, tasks_max)                },

        /* IO */
        { "IOWeight",               "t", NULL, offsetof(UnitLimitsInfo, io_weight)                },
        { "StartupIOWeight",        "t", NULL, offsetof(UnitLimitsInfo, startup_io_weight)        },

        /* Effective limits (accounting for parent slices) */
        { "EffectiveMemoryHigh",    "t", NULL, offsetof(UnitLimitsInfo, effective_memory_high)    },
        { "EffectiveMemoryMax",     "t", NULL, offsetof(UnitLimitsInfo, effective_memory_max)     },
        { "EffectiveTasksMax",      "t", NULL, offsetof(UnitLimitsInfo, effective_tasks_max)      },

        /* Current usage */
        { "MemoryCurrent",          "t", NULL, offsetof(UnitLimitsInfo, memory_current)           },
        { "MemorySwapCurrent",      "t", NULL, offsetof(UnitLimitsInfo, memory_swap_current)      },
        { "MemoryZSwapCurrent",     "t", NULL, offsetof(UnitLimitsInfo, memory_zswap_current)     },
        { "TasksCurrent",           "t", NULL, offsetof(UnitLimitsInfo, tasks_current)             },
        {},
};

typedef enum IoDeviceFormat {
        IO_DEVICE_FORMAT_WEIGHT,
        IO_DEVICE_FORMAT_BYTES,
        IO_DEVICE_FORMAT_IOPS,
        IO_DEVICE_FORMAT_USEC,
        _IO_DEVICE_FORMAT_MAX,
        _IO_DEVICE_FORMAT_INVALID = -EINVAL,
} IoDeviceFormat;

static int add_io_device_limits(
                Table *table,
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                const char *label,
                IoDeviceFormat format) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *dev;
        uint64_t value;
        int r;

        r = sd_bus_get_property(bus, "org.freedesktop.systemd1", path, interface, property, NULL, &reply, "a(st)");
        if (r < 0)
                return log_debug_errno(r, "Failed to get property '%s': %m", property);

        r = sd_bus_message_enter_container(reply, 'a', "(st)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(reply, "(st)", &dev, &value)) > 0) {
                r = table_add_cell(table, NULL, TABLE_FIELD, label);
                if (r < 0)
                        return table_log_add_error(r);

                switch (format) {

                case IO_DEVICE_FORMAT_WEIGHT:
                case IO_DEVICE_FORMAT_IOPS:
                        r = table_add_cell_stringf(table, NULL, "%s %" PRIu64, dev, value);
                        break;

                case IO_DEVICE_FORMAT_BYTES:
                        r = table_add_cell_stringf(table, NULL, "%s %s", dev, FORMAT_BYTES(value));
                        break;

                case IO_DEVICE_FORMAT_USEC:
                        r = table_add_cell_stringf(table, NULL, "%s %s", dev, FORMAT_TIMESPAN(value, USEC_PER_MSEC));
                        break;

                default:
                        assert_not_reached();
                }
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        return 0;
}

static int add_memory_limit(Table *table, const char *label, uint64_t val, uint64_t effective, uint64_t current) {
        int r;

        if (val != CGROUP_LIMIT_MAX) {
                bool show_effective = effective != CGROUP_LIMIT_MAX && effective != val;

                r = table_add_cell(table, NULL, TABLE_FIELD, label);
                if (r < 0)
                        return table_log_add_error(r);

                if (show_effective)
                        r = table_add_cell_stringf_full(table, NULL, TABLE_STRING_WITH_ANSI,
                                                        "%s %s(effective: %s)%s",
                                                        FORMAT_BYTES(val),
                                                        ansi_grey(), FORMAT_BYTES(effective), ansi_normal());
                else
                        r = table_add_cell(table, NULL, TABLE_STRING, FORMAT_BYTES(val));
                if (r < 0)
                        return table_log_add_error(r);
        } else if (effective != CGROUP_LIMIT_MAX) {
                r = table_add_cell(table, NULL, TABLE_FIELD, label);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf_full(table, NULL, TABLE_STRING_WITH_ANSI,
                                                "%s %s(inherited)%s",
                                                FORMAT_BYTES(effective),
                                                ansi_grey(), ansi_normal());
                if (r < 0)
                        return table_log_add_error(r);
        } else if (arg_all) {
                r = table_add_many(table,
                                   TABLE_FIELD, label,
                                   TABLE_STRING, "infinity");
                if (r < 0)
                        return table_log_add_error(r);
        } else
                return 0;

        /* Current usage column */
        if (current != UINT64_MAX)
                r = table_add_cell(table, NULL, TABLE_SIZE, &current);
        else
                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

static int add_memory_protection(Table *table, const char *label, uint64_t val, uint64_t current) {
        int r;

        if ((val > 0 && val != CGROUP_LIMIT_MAX) || arg_all) {
                r = table_add_many(table,
                                   TABLE_FIELD, label,
                                   TABLE_SIZE, val);
                if (r < 0)
                        return table_log_add_error(r);
        } else
                return 0;

        /* Current usage column */
        if (current != UINT64_MAX)
                r = table_add_cell(table, NULL, TABLE_SIZE, &current);
        else
                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

#define UNIT_LIMITS_INFO_INIT {                                         \
                .cpu_weight               = CGROUP_WEIGHT_INVALID,      \
                .startup_cpu_weight       = CGROUP_WEIGHT_INVALID,      \
                .cpu_quota_per_sec_usec   = USEC_INFINITY,              \
                .cpu_quota_period_usec    = USEC_INFINITY,              \
                .memory_min               = 0,                          \
                .memory_low               = 0,                          \
                .startup_memory_low       = 0,                          \
                .memory_high              = CGROUP_LIMIT_MAX,           \
                .startup_memory_high      = CGROUP_LIMIT_MAX,           \
                .memory_max               = CGROUP_LIMIT_MAX,           \
                .startup_memory_max       = CGROUP_LIMIT_MAX,           \
                .memory_swap_max          = CGROUP_LIMIT_MAX,           \
                .startup_memory_swap_max  = CGROUP_LIMIT_MAX,           \
                .memory_zswap_max         = CGROUP_LIMIT_MAX,           \
                .startup_memory_zswap_max = CGROUP_LIMIT_MAX,           \
                .tasks_max                = CGROUP_LIMIT_MAX,           \
                .io_weight                = CGROUP_WEIGHT_INVALID,      \
                .startup_io_weight        = CGROUP_WEIGHT_INVALID,      \
                .effective_memory_high    = CGROUP_LIMIT_MAX,           \
                .effective_memory_max     = CGROUP_LIMIT_MAX,           \
                .effective_tasks_max      = CGROUP_LIMIT_MAX,           \
                .memory_current           = UINT64_MAX,                 \
                .memory_swap_current      = UINT64_MAX,                 \
                .memory_zswap_current     = UINT64_MAX,                 \
                .tasks_current            = UINT64_MAX,                 \
        }

static int show_limits_for_unit(sd_bus *bus, const char *name) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *path = NULL;
        const char *interface;
        UnitLimitsInfo info = UNIT_LIMITS_INFO_INIT;
        TableCell *cell;
        int r;

        /* interface is only needed for the per-device IO array properties fetched individually below */
        interface = unit_dbus_interface_from_name(name);
        if (!interface)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid unit name: '%s'", name);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return log_oom();

        r = bus_map_all_properties(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        limits_map,
                        0,
                        &error,
                        &reply,
                        &info);
        if (r < 0)
                return log_error_errno(r, "Failed to get properties of '%s': %s", name, bus_error_message(&error, r));

        if (!info.load_state)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Failed to determine load state of '%s'.", name);

        if (STRPTR_IN_SET(info.load_state, "not-found", "error", "bad-setting"))
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Unit '%s' could not be loaded: %s", name, strna(info.load_state));

        if (streq_ptr(info.load_state, "masked"))
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Unit '%s' is masked.", name);

        printf("%s%s%s\n", ansi_highlight(), name, ansi_normal());

        table = table_new("PROPERTY", "LIMIT", "CURRENT USAGE");
        if (!table)
                return log_oom();

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        /* CPU */
        if (info.cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = table_add_many(table,
                                   TABLE_FIELD, "CPU Weight",
                                   TABLE_UINT64, info.cpu_weight,
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info.startup_cpu_weight != CGROUP_WEIGHT_INVALID) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Startup CPU Weight",
                                   TABLE_UINT64, info.startup_cpu_weight,
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info.cpu_quota_per_sec_usec != USEC_INFINITY) {
                r = table_add_cell(table, NULL, TABLE_FIELD, "CPU Quota");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%g%%",
                                           (double) info.cpu_quota_per_sec_usec / (double) USEC_PER_SEC * 100.0);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
        } else if (arg_all) {
                r = table_add_many(table,
                                   TABLE_FIELD, "CPU Quota",
                                   TABLE_STRING, "infinity",
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info.cpu_quota_period_usec != USEC_INFINITY) {
                r = table_add_many(table,
                                   TABLE_FIELD, "CPU Quota Period",
                                   TABLE_TIMESPAN_MSEC, info.cpu_quota_period_usec,
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Memory */
        r = add_memory_protection(table, "Memory Min", info.memory_min, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_protection(table, "Memory Low", info.memory_low, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_protection(table, "Startup Memory Low", info.startup_memory_low, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Memory High", info.memory_high, info.effective_memory_high, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Startup Memory High", info.startup_memory_high, CGROUP_LIMIT_MAX, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Memory Max", info.memory_max, info.effective_memory_max, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Startup Memory Max", info.startup_memory_max, CGROUP_LIMIT_MAX, info.memory_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Memory Swap Max", info.memory_swap_max, CGROUP_LIMIT_MAX, info.memory_swap_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Startup Memory Swap Max", info.startup_memory_swap_max, CGROUP_LIMIT_MAX, info.memory_swap_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Memory ZSwap Max", info.memory_zswap_max, CGROUP_LIMIT_MAX, info.memory_zswap_current);
        if (r < 0)
                return r;

        r = add_memory_limit(table, "Startup Memory ZSwap Max", info.startup_memory_zswap_max, CGROUP_LIMIT_MAX, info.memory_zswap_current);
        if (r < 0)
                return r;

        /* Tasks */
        if (info.tasks_max != CGROUP_LIMIT_MAX ||
            info.effective_tasks_max != CGROUP_LIMIT_MAX ||
            arg_all) {
                bool show_effective = info.effective_tasks_max != CGROUP_LIMIT_MAX && info.effective_tasks_max != info.tasks_max;

                r = table_add_cell(table, NULL, TABLE_FIELD, "Tasks Max");
                if (r < 0)
                        return table_log_add_error(r);

                if (info.tasks_max != CGROUP_LIMIT_MAX && show_effective)
                        r = table_add_cell_stringf_full(table, NULL, TABLE_STRING_WITH_ANSI,
                                                        "%" PRIu64 " %s(effective: %" PRIu64 ")%s",
                                                        info.tasks_max,
                                                        ansi_grey(), info.effective_tasks_max, ansi_normal());
                else if (info.tasks_max != CGROUP_LIMIT_MAX)
                        r = table_add_many(table, TABLE_UINT64, info.tasks_max);
                else if (info.effective_tasks_max != CGROUP_LIMIT_MAX)
                        r = table_add_cell_stringf_full(table, NULL, TABLE_STRING_WITH_ANSI,
                                                        "%" PRIu64 " %s(inherited)%s",
                                                        info.effective_tasks_max,
                                                        ansi_grey(), ansi_normal());
                else
                        r = table_add_cell(table, NULL, TABLE_STRING, "infinity");
                if (r < 0)
                        return table_log_add_error(r);

                if (info.tasks_current != UINT64_MAX)
                        r = table_add_many(table, TABLE_UINT64, info.tasks_current);
                else
                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* IO */
        if (info.io_weight != CGROUP_WEIGHT_INVALID) {
                r = table_add_many(table,
                                   TABLE_FIELD, "IO Weight",
                                   TABLE_UINT64, info.io_weight,
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (info.startup_io_weight != CGROUP_WEIGHT_INVALID) {
                r = table_add_many(table,
                                   TABLE_FIELD, "Startup IO Weight",
                                   TABLE_UINT64, info.startup_io_weight,
                                   TABLE_EMPTY);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Per-device IO limits — these are a(st) arrays, fetched individually */
        (void) add_io_device_limits(table, bus, path, interface, "IODeviceWeight", "IO Device Weight", IO_DEVICE_FORMAT_WEIGHT);
        (void) add_io_device_limits(table, bus, path, interface, "IOReadBandwidthMax", "IO Read Bandwidth Max", IO_DEVICE_FORMAT_BYTES);
        (void) add_io_device_limits(table, bus, path, interface, "IOWriteBandwidthMax", "IO Write Bandwidth Max", IO_DEVICE_FORMAT_BYTES);
        (void) add_io_device_limits(table, bus, path, interface, "IOReadIOPSMax", "IO Read IOPS Max", IO_DEVICE_FORMAT_IOPS);
        (void) add_io_device_limits(table, bus, path, interface, "IOWriteIOPSMax", "IO Write IOPS Max", IO_DEVICE_FORMAT_IOPS);
        (void) add_io_device_limits(table, bus, path, interface, "IODeviceLatencyTargetUSec", "IO Device Latency Target", IO_DEVICE_FORMAT_USEC);

        if (table_isempty(table))
                printf("  No resource limits configured.\n");
        else {
                r = table_print(table, NULL);
                if (r < 0)
                        return table_log_print_error(r);
        }

        return 0;
}

int verb_limits(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_strv_free_ char **names = NULL;
        sd_bus *bus;
        int r, ret = 0;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        r = expand_unit_names(bus, strv_skip(argv, 1), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");

        STRV_FOREACH(name, names) {
                if (name != names)
                        printf("\n");

                r = show_limits_for_unit(bus, *name);
                if (r < 0)
                        RET_GATHER(ret, r);
        }

        return ret;
}
