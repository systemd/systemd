/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int on_ac_power(void);

int battery_is_discharging_and_low(void);

int battery_enumerator_new(sd_device_enumerator **ret);
int battery_read_capacity_percentage(sd_device *dev);
