/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-device.h"
#include "device.h"
#include "unit.h"

const sd_bus_vtable bus_device_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("SysFSPath", "s", NULL, offsetof(Device, sysfs), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};
