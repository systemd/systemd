/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <dirent.h>
#include <errno.h>

#include "unit.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"
#include "unit-name.h"
#include "conf-parser.h"
#include "load-fragment.h"

static int load_dropin_config_file(Unit *u, const char *path) {
        assert(u);
        assert(path);

        if (!endswith(path, ".conf"))
                return 0;

        return config_parse(path, NULL, UNIT_VTABLE(u)->sections, config_item_perf_lookup, (void*) load_fragment_gperf_lookup, false, u);
}

static int iterate_dir(Unit *u, const char *path, UnitDependency dependency) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(u);
        assert(path);

        d = opendir(path);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        for (;;) {
                struct dirent *de;
                union dirent_storage buf;
                _cleanup_free_ char *f = NULL;
                int k;

                k = readdir_r(d, &buf.de, &de);
                if (k != 0) {
                        log_error("Failed to read directory %s: %s", path, strerror(k));
                        return -k;
                }

                if (!de)
                        break;

                if (ignore_file(de->d_name))
                        continue;

                f = strjoin(path, "/", de->d_name, NULL);
                if (!f)
                        return log_oom();

                if (dependency >= 0) {
                        r = unit_add_dependency_by_name(u, dependency, de->d_name, f, true);
                        if (r < 0)
                                log_error("Cannot add dependency %s to %s, ignoring: %s", de->d_name, u->id, strerror(-r));
                } else {
                        r = load_dropin_config_file(u, f);
                        if (r < 0)
                                log_error("Cannot load drop-in configuration file %s for %s, ignoring: %s", f, u->id, strerror(-r));
                }
        }

        return 0;
}

static int process_dir(Unit *u, const char *unit_path, const char *name, const char *suffix, UnitDependency dependency) {
        int r;
        char *path;

        assert(u);
        assert(unit_path);
        assert(name);
        assert(suffix);

        path = strjoin(unit_path, "/", name, suffix, NULL);
        if (!path)
                return -ENOMEM;

        if (u->manager->unit_path_cache &&
            !set_get(u->manager->unit_path_cache, path))
                r = 0;
        else
                r = iterate_dir(u, path, dependency);
        free(path);

        if (r < 0)
                return r;

        if (u->instance) {
                char *template;
                /* Also try the template dir */

                template = unit_name_template(name);
                if (!template)
                        return -ENOMEM;

                path = strjoin(unit_path, "/", template, suffix, NULL);
                free(template);

                if (!path)
                        return -ENOMEM;

                if (u->manager->unit_path_cache &&
                    !set_get(u->manager->unit_path_cache, path))
                        r = 0;
                else
                        r = iterate_dir(u, path, dependency);
                free(path);

                if (r < 0)
                        return r;
        }

        return 0;
}

int unit_load_dropin(Unit *u) {
        Iterator i;
        char *t;

        assert(u);

        /* Load dependencies from supplementary drop-in directories */

        SET_FOREACH(t, u->names, i) {
                char **p;

                STRV_FOREACH(p, u->manager->lookup_paths.unit_path) {
                        int r;

                        r = process_dir(u, *p, t, ".wants", UNIT_WANTS);
                        if (r < 0)
                                return r;

                        r = process_dir(u, *p, t, ".requires", UNIT_REQUIRES);
                        if (r < 0)
                                return r;

                        /* This loads the drop-in config snippets */
                        r = process_dir(u, *p, t, ".d", _UNIT_TYPE_INVALID);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
