/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "timesyncd-forward.h"

extern const BusObjectImplementation manager_object;

int manager_connect_bus(Manager *m);
