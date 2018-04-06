/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include "dbus-target.h"
#include "unit.h"

const sd_bus_vtable bus_target_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_VTABLE_END
};
