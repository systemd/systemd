/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

static int iterate_dir(Unit *u, const char *path) {
        DIR *d;
        struct dirent *de;
        int r;

        if (!(d = opendir(path))) {

                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        while ((de = readdir(d))) {
                char *f;

                if (ignore_file(de->d_name))
                        continue;

                if (asprintf(&f, "%s/%s", path, de->d_name) < 0) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = unit_add_dependency_by_name(u, UNIT_WANTS, de->d_name, f, true);
                free(f);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        closedir(d);
        return r;
}

int unit_load_dropin(Unit *u) {
        Iterator i;
        int r;
        char *t;

        assert(u);

        /* Load dependencies from supplementary drop-in directories */

        SET_FOREACH(t, u->meta.names, i) {
                char *path;
                char **p;

                STRV_FOREACH(p, u->meta.manager->unit_path) {

                        if (asprintf(&path, "%s/%s.wants", *p, t) < 0)
                                return -ENOMEM;

                        r = iterate_dir(u, path);
                        free(path);

                        if (r < 0)
                                return r;

                        if (u->meta.instance) {
                                char *template;
                                /* Also try the template dir */

                                if (!(template = unit_name_template(t)))
                                        return -ENOMEM;

                                r = asprintf(&path, "%s/%s.wants", *p, template);
                                free(template);

                                if (r < 0)
                                        return -ENOMEM;

                                r = iterate_dir(u, path);
                                free(path);

                                if (r < 0)
                                        return r;
                        }

                }
        }

        return 0;
}
