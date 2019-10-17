/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "hashmap.h"
#include "sd-device.h"

sd_device **device_trigger_get_devices(sd_device_trigger *trigger, size_t *ret_n_devices);
Hashmap *device_trigger_get_properties(sd_device_trigger *trigger);
