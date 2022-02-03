/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int find_device(const char *id, const char *prefix, sd_device **ret);
int find_device_with_action(const char *id, sd_device_action_t action, sd_device **ret);
int parse_device_action(const char *str, sd_device_action_t *action);
