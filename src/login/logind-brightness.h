/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"
#include "sd-device.h"

#include "logind.h"

int manager_write_brightness(Manager *m, sd_device *device, uint32_t brightness, sd_bus_message *message);
