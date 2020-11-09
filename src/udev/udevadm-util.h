/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "sd-device.h"

int find_device(const char *id, const char *prefix, sd_device **ret);
