/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "time-util.h"

typedef struct Manager Manager;

int manager_start_varlink_server(Manager *manager);
int udev_varlink_connect(sd_varlink **ret, usec_t timeout);
