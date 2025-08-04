/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "analyze.h"
#include "analyze-unit-paths.h"
#include "path-lookup.h"
#include "strv.h"

int verb_unit_paths(int argc, char *argv[], void *userdata) {
        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        int r;

        r = lookup_paths_init_or_warn(&paths, arg_runtime_scope, 0, NULL);
        if (r < 0)
                return r;

        STRV_FOREACH(p, paths.search_path)
                puts(*p);

        return 0;
}
