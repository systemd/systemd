/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fs-util.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "log.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"

static int process_deps(Unit *u, UnitDependency dependency, const char *dir_suffix) {
        _cleanup_strv_free_ char **paths = NULL;
        int r;

        r = unit_file_find_dropin_paths(NULL,
                                        u->manager->lookup_paths.search_path,
                                        u->manager->unit_path_cache,
                                        dir_suffix, NULL,
                                        u->id, u->aliases,
                                        &paths);
        if (r < 0)
                return r;

        STRV_FOREACH(p, paths) {
                _cleanup_free_ char *target = NULL;
                const char *entry;

                entry = basename(*p);

                if (null_or_empty_path(*p) > 0) {
                        /* an error usually means an invalid symlink, which is not a mask */
                        log_unit_debug(u, "%s dependency on %s is masked by %s, ignoring.",
                                       unit_dependency_to_string(dependency), entry, *p);
                        continue;
                }

                r = is_symlink(*p);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "%s dropin %s unreadable, ignoring: %m",
                                               unit_dependency_to_string(dependency), *p);
                        continue;
                }
                if (r == 0) {
                        log_unit_warning(u, "%s dependency dropin %s is not a symlink, ignoring.",
                                         unit_dependency_to_string(dependency), *p);
                        continue;
                }

                if (!unit_name_is_valid(entry, UNIT_NAME_ANY)) {
                        log_unit_warning(u, "%s dependency dropin %s is not a valid unit name, ignoring.",
                                         unit_dependency_to_string(dependency), *p);
                        continue;
                }

                r = readlink_malloc(*p, &target);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "readlink(\"%s\") failed, ignoring: %m", *p);
                        continue;
                }

                /* We don't treat this as an error, especially because we didn't check this for a
                 * long time. Nevertheless, we warn, because such mismatch can be mighty confusing. */
                r = unit_symlink_name_compatible(entry, basename(target), u->instance);
                if (r < 0) {
                        log_unit_warning_errno(u, r, "Can't check if names %s and %s are compatible, ignoring: %m",
                                               entry, basename(target));
                        continue;
                }
                if (r == 0)
                        log_unit_warning(u, "%s dependency dropin %s target %s has different name",
                                         unit_dependency_to_string(dependency), *p, target);

                r = unit_add_dependency_by_name(u, dependency, entry, true, UNIT_DEPENDENCY_FILE);
                if (r < 0)
                        log_unit_warning_errno(u, r, "Cannot add %s dependency on %s, ignoring: %m",
                                               unit_dependency_to_string(dependency), entry);
        }

        return 0;
}

int unit_load_dropin(Unit *u) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(u);

        /* Load dependencies from .wants and .requires directories */
        r = process_deps(u, UNIT_WANTS, ".wants");
        if (r < 0)
                return r;

        r = process_deps(u, UNIT_REQUIRES, ".requires");
        if (r < 0)
                return r;

        /* Load .conf dropins */
        r = unit_find_dropin_paths(u, &l);
        if (r <= 0)
                return 0;

        if (!u->dropin_paths)
                u->dropin_paths = TAKE_PTR(l);
        else {
                r = strv_extend_strv(&u->dropin_paths, l, true);
                if (r < 0)
                        return log_oom();
        }

        u->dropin_mtime = 0;
        STRV_FOREACH(f, u->dropin_paths) {
                struct stat st;

                r = config_parse(u->id, *f, NULL,
                                 UNIT_VTABLE(u)->sections,
                                 config_item_perf_lookup, load_fragment_gperf_lookup,
                                 0, u, &st);
                if (r > 0)
                        u->dropin_mtime = MAX(u->dropin_mtime, timespec_load(&st.st_mtim));
        }

        return 0;
}
