/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-device.h"

#include "hashmap.h"
#include "set.h"

int update_match_strv(Hashmap **match_strv, const char *key, const char *value, bool clear_on_null);
bool device_match_sysattr(sd_device *device, Hashmap *match_sysattr, Hashmap *nomatch_sysattr);
bool device_match_parent(sd_device *device, Set *match_parent, Set *nomatch_parent);
