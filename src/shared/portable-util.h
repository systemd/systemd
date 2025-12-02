/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "constants.h"
#include "shared-forward.h"

#define PORTABLE_PROFILE_DIRS CONF_PATHS_NULSTR("systemd/portable/profile")

int portable_profile_dirs(RuntimeScope scope, char ***ret);
int find_portable_profile(RuntimeScope scope, const char *name, const char *unit, char **ret_path);
