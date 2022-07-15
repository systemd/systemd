/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dbus-target.h"
#include "unit.h"

const sd_bus_vtable bus_target_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_VTABLE_END
};
