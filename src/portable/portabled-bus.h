/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "portable.h"

extern const sd_bus_vtable manager_vtable[];

int reply_portable_changes(sd_bus_message *m, const PortableChange *changes, size_t n_changes);
int reply_portable_changes_pair(sd_bus_message *m, const PortableChange *changes_first, size_t n_changes_first, const PortableChange *changes_second, size_t n_changes_second);
