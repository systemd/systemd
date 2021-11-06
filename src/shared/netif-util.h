/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-device.h"

int net_get_type_string(sd_device *device, uint16_t iftype, char **ret);
const char *net_get_name_persistent(sd_device *device);
int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *ret);
