/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dirent.h>
#include <errno.h>

#include "unit.h"
#include "load-dropin.h"
#include "log.h"
#include "strv.h"
#include "unit-name.h"

static int iterate_dir(Unit *u, const char *path, UnitDependency dependency) {
        DIR *d;
        struct dirent *de;
        int r;

        assert(u);
        assert(path);

        d = opendir(path);
        if (!d) {

                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        while ((de = readdir(d))) {
                char *f;

                if (ignore_file(de->d_name))
                        continue;

                f = join(path, "/", de->d_name, NULL);
                if (!f) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = unit_add_dependency_by_name(u, dependency, de->d_name, f, true);
                free(f);

                if (r < 0)
                        log_error("Cannot add dependency %s to %s, ignoring: %s", de->d_name, u->meta.id, strerror(-r));
        }

        r = 0;

finish:
        closedir(d);
        return r;
}

static int process_dir(Unit *u, const char *unit_path, const char *name, const char *suffix, UnitDependency dependency) {
        int r;
        char *path;

        assert(u);
        assert(unit_path);
        assert(name);
        assert(suffix);

        path = join(unit_path, "/", name, suffix, NULL);
        if (!path)
                return -ENOMEM;

        if (u->meta.manager->unit_path_cache &&
            !set_get(u->meta.manager->unit_path_cache, path))
                r = 0;
        else
                r = iterate_dir(u, path, dependency);
        free(path);

        if (r < 0)
                return r;

        if (u->meta.instance) {
                char *template;
                /* Also try the template dir */

                template = unit_name_template(name);
                if (!template)
                        return -ENOMEM;

                path = join(unit_path, "/", template, suffix, NULL);
                free(template);

                if (!path)
                        return -ENOMEM;

                if (u->meta.manager->unit_path_cache &&
                    !set_get(u->meta.manager->unit_path_cache, path))
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

        SET_FOREACH(t, u->meta.names, i) {
                char **p;

                STRV_FOREACH(p, u->meta.manager->lookup_paths.unit_path) {
                        int r;

                        r = process_dir(u, *p, t, ".wants", UNIT_WANTS);
                        if (r < 0)
                                return r;

                        r = process_dir(u, *p, t, ".requires", UNIT_REQUIRES);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
