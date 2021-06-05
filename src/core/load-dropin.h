/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dropin.h"
#include "unit.h"

/* Read service data supplementary drop-in directories */

static inline int unit_find_dropin_paths(Unit *u, char ***paths) {
        assert(u);

        return unit_file_find_dropin_paths(NULL,
                                           u->manager->lookup_paths.search_path,
                                           u->manager->unit_path_cache,
                                           ".d", ".conf",
                                           u->id, u->aliases,
                                           paths);
}

int unit_load_dropin(Unit *u);
