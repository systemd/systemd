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
#include "path-util.h"
#include "stat-util.h"
#include "strv.h"
#include "unit-name.h"
#include "unit.h"


typedef struct DependencyConsumerData {
        Unit *unit;
        int depth;
} DependencyConsumerData;

typedef struct DropinSymlink {
        Unit *unit;
        UnitDependency dependency;
        int depth;              /* path depth used when merging 2 dropins */
        bool is_mask;           /* does the symlink points to /dev/null ? */
} DropinSymlink;

static void dropin_hash_func(const void *p, struct siphash *state) {
        const DropinSymlink *ds = p;

        siphash24_compress(&ds->unit, sizeof(ds->unit), state);
}

static int dropin_compare_func(const void *_a, const void *_b) {
        const DropinSymlink *a = _a;
        const DropinSymlink *b = _b;

        if (a->unit != b->unit)
                return -1;

        if (a->dependency != b->dependency)
                return 1;

        return 0;
}

static const struct hash_ops dropin_hash_ops = {
        .hash = dropin_hash_func,
        .compare = dropin_compare_func,
};

/* Return true only if path is a symlink to /dev/null. Anything
 * else (specially dangling symlinks) should return false. */
static bool symlink_to_devnull(const char *path) {
        _cleanup_free_ char *target = NULL;

        assert(path);

        if (readlink_malloc(path, &target) < 0)
                return false;

        return path_equal(target, "/dev/null");
}

int unit_load_reserve_deferred_dropin_dependencies(Unit *u) {
        DropinSymlink *ds;
        Iterator i;
        int r = 0;

        SET_FOREACH(ds, u->deferred_dropin_dependencies, i) {
                r = unit_reserve_dependency(u, ds->dependency, ds->unit, true);
                if (r < 0)
                        break;
        }
        return r;
}

static void unit_load_solve_dropin_dependencies(Unit *u) {
        DropinSymlink *ds1, *ds2;
        Iterator i, j;

        assert(u);

        /* If one of the dropin unit has not been loaded yet,
         * we defer the loading of the dropins for 'u' further
         * until the last dropin is loaded. */
        SET_FOREACH(ds1, u->deferred_dropin_dependencies, i)
                if (ds1->unit->load_state == UNIT_STUB)
                        return;

        SET_FOREACH(ds1, u->deferred_dropin_dependencies, i) {
                DropinSymlink best;

                if (!ds1->unit)
                        continue;

                best = *ds1;      /* struct copy */
                best.unit = unit_follow_merge(best.unit);
                ds1->unit = NULL; /* mark this dropin as processed. */

                if (best.unit->load_state == UNIT_LOADED)
                        SET_FOREACH(ds2, u->deferred_dropin_dependencies, j) {

                                if (!ds2->unit)
                                        continue;

                                if (best.dependency != ds2->dependency)
                                        continue;

                                if (best.unit != unit_follow_merge(ds2->unit))
                                        continue;

                                /* Same dropin on the same depth is unlikely but if
                                 * it happens and one of them is a mask then gives
                                 * priority to the mask. */
                                if (best.depth > ds2->depth ||
                                    ((best.depth == ds2->depth && ds2->is_mask)))
                                        best = *ds2;

                                /* mark this dropin as processed. */
                                ds2->unit = NULL;
                        }

                if (best.is_mask)
                        continue;

                /* This can't fail as we did a reservation. */
                assert(unit_add_dependency(u, best.dependency, best.unit, true) >= 0);
        }

        u->deferred_dropin_dependencies = set_free_free(u->deferred_dropin_dependencies);
}

void unit_load_deferred_dropin_dependencies(Unit *u) {
        Iterator i;
        Unit *o;

        /* Let's find out if we're involved in the deferred dep of
         * another unit and the later is waiting for us to solve the
         * dropin dep, IOW if we're the last loaded deferred dep. */
        SET_FOREACH(o, u->deferred_dropin_units, i)
                unit_load_solve_dropin_dependencies(o);

        /* We shouldn't be called again for this unit as it is going
         * to be in loaded state, so 'deferred_dropin_units' set
         * shouldn't be needed anymore. */
        u->deferred_dropin_units = set_free(u->deferred_dropin_units);
}

static int add_dependency_consumer(
                UnitDependency dependency,
                const char *entry,
                const char *filepath,
                void *arg) {
        _cleanup_free_ DropinSymlink *ds = NULL;
        DependencyConsumerData *data = arg;
        Unit *u, *other;
        int r;

        assert(data);

        u = data->unit;

        /* Here's the deal: the dependency unit needs to be loaded so we can
         * deal with aliases (if any) properly. But as we're already in the
         * loading path this cannot be achieved here (if it's needed)...
         * Therefore we defer the handling of the dropins during their own
         * unit loading. */
        other = manager_get_unit(u->manager, entry);
        if (!other) {
                /* Force 'filepath' to NULL because the symlink is not supposed
                 * to define any aliases and a symlink to /dev/null indicates
                 * a dropin mask, not that the unit should be masked. */
                r = manager_load_unit_prepare(u->manager, entry, NULL, NULL, &other);
                if (r < 0)
                        return r;
        }

        r = set_ensure_allocated(&u->deferred_dropin_dependencies, &dropin_hash_ops);
        if (r < 0)
                return r;

        r = set_ensure_allocated(&other->deferred_dropin_units, NULL);
        if (r < 0)
                return r;

        ds = new0(DropinSymlink, 1);
        if (!ds)
                return -ENOMEM;

        ds->unit = other;
        ds->depth = data->depth;
        ds->dependency = dependency;
        ds->is_mask = symlink_to_devnull(filepath);

        r = set_put(u->deferred_dropin_dependencies, ds);
        if (r <= 0)
                /* r == 0 means we already registered the same dependency
                 * for 'u' but with a higher priority (lower depth). */
                return r;

        r = set_put(other->deferred_dropin_units, u);
        if (r < 0) {
                set_remove(u->deferred_dropin_dependencies, ds);
                return r;
        }

        ds = NULL;
        return 0;
}

int unit_load_dropin(Unit *u) {
        DependencyConsumerData data = { .unit = u, .depth = 0 };
        _cleanup_strv_free_ char **l = NULL;
        Iterator i;
        char **f, **p;
        int r;

        assert(u);

        /* Load dependencies from supplementary drop-in directories */

        STRV_FOREACH(p, u->manager->lookup_paths.search_path) {
                char *t;

                SET_FOREACH(t, u->names, i) {
                        unit_file_process_dir(u->manager->unit_path_cache, *p, t, ".wants",
                                              UNIT_WANTS,
                                              add_dependency_consumer, &data, NULL);
                        unit_file_process_dir(u->manager->unit_path_cache, *p, t, ".requires",
                                              UNIT_REQUIRES,
                                              add_dependency_consumer, &data, NULL);
                }
                data.depth++;
        }

        /* Try to load the deferred dependencies now just in
         * case all dropins have been already loaded. */
        r = unit_load_reserve_deferred_dropin_dependencies(u);
        if (r < 0)
                return r;
        unit_load_solve_dropin_dependencies(u);

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
