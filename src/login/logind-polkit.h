/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct Manager Manager;

int check_polkit_chvt(sd_bus_message *message, Manager *manager, sd_bus_error *error);
