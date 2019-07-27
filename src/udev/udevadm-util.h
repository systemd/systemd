/* SPDX-License-Identifier: GPL-2.0+ */
#pragma once

#include "sd-device.h"

int find_device(const char *id, const char *prefix, sd_device **ret);
