/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "udev-forward.h"

int manager_start_varlink_server(Manager *manager, int fd);
int udev_varlink_connect(sd_varlink **ret, usec_t timeout);
