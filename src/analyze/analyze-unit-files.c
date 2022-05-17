/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-unit-files.h"
#include "path-lookup.h"
#include "strv.h"

static bool strv_fnmatch_strv_or_empty(char* const* patterns, char **strv, int flags) {
        STRV_FOREACH(s, strv)
                if (strv_fnmatch_or_empty(patterns, *s, flags))
                        return true;

        return false;
}

int verb_unit_files(int argc, char *argv[], void *userdata) {
        _cleanup_hashmap_free_ Hashmap *unit_ids = NULL, *unit_names = NULL;
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        char **patterns = strv_skip(argv, 1);
        const char *k, *dst;
        char **v;
        int r;

        r = lookup_paths_init_or_warn(&lp, arg_scope, 0, NULL);
        if (r < 0)
                return r;

        r = unit_file_build_name_map(&lp, NULL, &unit_ids, &unit_names, NULL);
        if (r < 0)
                return log_error_errno(r, "unit_file_build_name_map() failed: %m");

        HASHMAP_FOREACH_KEY(dst, k, unit_ids) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_or_empty(patterns, dst, FNM_NOESCAPE))
                        continue;

                printf("ids: %s → %s\n", k, dst);
        }

        HASHMAP_FOREACH_KEY(v, k, unit_names) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_strv_or_empty(patterns, v, FNM_NOESCAPE))
                        continue;

                _cleanup_free_ char *j = strv_join(v, ", ");
                printf("aliases: %s ← %s\n", k, j);
        }

        return EXIT_SUCCESS;
}
