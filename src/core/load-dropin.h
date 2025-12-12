/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* Read service data supplementary drop-in directories */

int unit_find_dropin_paths(Unit *u, bool use_unit_path_cache, char ***paths);

int unit_load_dropin(Unit *u);
