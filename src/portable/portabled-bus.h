/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "portable.h"

extern const sd_bus_vtable manager_vtable[];

int reply_portable_changes(sd_bus_message *m, const PortableChange *changes, size_t n_changes);
