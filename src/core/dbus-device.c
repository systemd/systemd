/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-device.h"
#include "device.h"
#include "unit.h"

/* Note: when adding a SD_BUS_WRITABLE_PROPERTY or SD_BUS_METHOD add a TODO(selinux),
 *       so the SELinux people can add a permission check.
 */
const sd_bus_vtable bus_device_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("SysFSPath", "s", NULL, offsetof(Device, sysfs), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_VTABLE_END
};
