/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "constants.h"
#include "macro.h"

#define PORTABLE_PROFILE_DIRS CONF_PATHS_NULSTR("systemd/portable/profile")

int find_portable_profile(const char *name, const char *unit, char **ret_path);
