/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

typedef struct Manager Manager;

extern const sd_bus_vtable manager_vtable[];

int manager_send_changed_strv(Manager *m, char **properties);
