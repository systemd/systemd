/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "bus-locator.h"

int verb_log_control_common(sd_bus *bus, const char *destination, const char *verb, const char *value);
