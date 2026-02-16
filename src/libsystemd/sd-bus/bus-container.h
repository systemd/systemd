/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

int container_get_leader(RuntimeScope scope, const char *machine, pid_t *ret);

int bus_container_connect_socket(sd_bus *b);
