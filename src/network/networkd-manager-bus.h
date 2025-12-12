/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

extern const BusObjectImplementation manager_object;

int manager_send_changed_strv(Manager *m, char **properties);
