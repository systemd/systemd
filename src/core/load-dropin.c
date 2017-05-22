/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/


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

static int unit_name_compatible(const char *a, const char *b) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        /* the straightforward case: the symlink name matches the target */
        if (streq(a, b))
                return 1;

        r = unit_name_template(a, &prefix);
        if (r == -EINVAL)
                /* not a template */
                return 0;
        if (r < 0)
                /* oom, or some other failure. Just skip the warning. */
                return r;

        /* an instance name points to a target that is just the template name */
        if (streq(prefix, b))
                return 1;

        return 0;
}

static int process_deps(Unit *u, UnitDependency dependency, const char *dir_suffix) {
        _cleanup_strv_free_ char **paths = NULL;
        char **p;
        int r;

        r = unit_file_find_dropin_paths(NULL,
                                        u->manager->lookup_paths.search_path,
                                        u->manager->unit_path_cache,
                                        dir_suffix,
                                        NULL,
                                        u->names,
                                        &paths);
        if (r < 0)
                return r;

        STRV_FOREACH(p, paths) {
                const char *entry;
                _cleanup_free_ char *target = NULL;

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
                r = unit_name_compatible(entry, basename(target));
                if (r < 0) {
                        log_unit_warning_errno(u, r, "Can't check if names %s and %s are compatible, ignoring: %m", entry, basename(target));
                        continue;
                }
                if (r == 0)
                        log_unit_warning(u, "%s dependency dropin %s target %s has different name",
                                         unit_dependency_to_string(dependency), *p, target);

                r = unit_add_dependency_by_name(u, dependency, entry, *p, true);
                if (r < 0)
                        log_unit_error_errno(u, r, "cannot add %s dependency on %s, ignoring: %m",
                                             unit_dependency_to_string(dependency), entry);
        }

        return 0;
}

int unit_load_dropin(Unit *u) {
        _cleanup_strv_free_ char **l = NULL;
        char **f;
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

        if (!u->dropin_paths) {
                u->dropin_paths = l;
                l = NULL;
        } else {
                r = strv_extend_strv(&u->dropin_paths, l, true);
                if (r < 0)
                        return log_oom();
        }

        STRV_FOREACH(f, u->dropin_paths) {
                config_parse(u->id, *f, NULL,
                             UNIT_VTABLE(u)->sections,
                             config_item_perf_lookup, load_fragment_gperf_lookup,
                             false, false, false, u);
        }

        u->dropin_mtime = now(CLOCK_REALTIME);

        return 0;
}
