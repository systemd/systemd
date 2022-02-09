/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-get-properties.h"
#include "cgroup-util.h"
#include "dbus-device.h"
#include "device.h"
#include "unit.h"

static BUS_DEFINE_PROPERTY_GET_ENUM(property_get_iocost_ctrl, io_cost_ctrl, IOCostCtrl);

static int property_get_io_cost_qos_scaling_percentage(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        loadavg_t io_cost_qos_scaling_percentage = *(loadavg_t *) userdata;
        uint32_t result;

        assert(bus);
        assert(reply);

        /* range supported by the kernel */
        if (LOADAVG_INT_SIDE(io_cost_qos_scaling_percentage) < 1 || LOADAVG_INT_SIDE(io_cost_qos_scaling_percentage) > 10000)
                result = 0;
        else
                result = LOADAVG_INT_SIDE(io_cost_qos_scaling_percentage) * 100 + LOADAVG_DECIMAL_SIDE(io_cost_qos_scaling_percentage);
        return sd_bus_message_append_basic(reply, 'u', &result);
}

const sd_bus_vtable bus_device_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("SysFSPath", "s", NULL, offsetof(Device, sysfs), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSEnabled", "b", NULL, offsetof(Device, io_cost_qos.enabled), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSCtrl", "s", property_get_iocost_ctrl, offsetof(Device, io_cost_qos.ctrl), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSRPercentile", "u", NULL, offsetof(Device, io_cost_qos.read_latency_percentile), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSRLat", "u", bus_property_get_unsigned, offsetof(Device, io_cost_qos.read_latency_threshold), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSWPercentile", "u", NULL, offsetof(Device, io_cost_qos.write_latency_percentile), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSWLat", "u", bus_property_get_unsigned, offsetof(Device, io_cost_qos.write_latency_threshold), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSMin", "u", property_get_io_cost_qos_scaling_percentage, offsetof(Device, io_cost_qos.min), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostQOSMax", "u", property_get_io_cost_qos_scaling_percentage, offsetof(Device, io_cost_qos.max), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelCtrl", "s", property_get_iocost_ctrl, offsetof(Device, io_cost_model.ctrl), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelRbps", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.rbps), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelRSeqIops", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.rseqiops), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelRRandIops", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.rrandiops), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelWbps", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.wbps), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelWSeqIops", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.wseqiops), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("IOCostModelWRandIops", "t", bus_property_get_ulong, offsetof(Device, io_cost_model.wrandiops), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};
