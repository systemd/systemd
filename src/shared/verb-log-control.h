/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int verb_log_control_common(sd_bus *bus, const char *destination, const char *verb, const char *value);

int varlink_get_log_level_string(sd_varlink *vl, char **ret);
int varlink_set_log_level_string(sd_varlink *vl, const char *value);
