/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-object.h"
#include "forward.h"

typedef struct Manager Manager;

extern const BusObjectImplementation manager_object;

int manager_send_changed_strv(Manager *m, char **properties);
