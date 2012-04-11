/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include "cgroup-attr.h"
#include "cgroup-util.h"
#include "list.h"

int cgroup_attribute_apply(CGroupAttribute *a, CGroupBonding *b) {
        int r;
        char *path = NULL;
        char *v = NULL;

        assert(a);

        b = cgroup_bonding_find_list(b, a->controller);
        if (!b)
                return 0;

        if (a->map_callback) {
                r = a->map_callback(a->controller, a->name, a->value, &v);
                if (r < 0)
                        return r;
        }

        r = cg_get_path(a->controller, b->path, a->name, &path);
        if (r < 0) {
                free(v);
                return r;
        }

        r = write_one_line_file(path, v ? v : a->value);
        if (r < 0)
                log_warning("Failed to write '%s' to %s: %s", v ? v : a->value, path, strerror(-r));

        free(path);
        free(v);

        return r;
}

int cgroup_attribute_apply_list(CGroupAttribute *first, CGroupBonding *b) {
        CGroupAttribute *a;
        int r = 0;

        LIST_FOREACH(by_unit, a, first) {
                int k;

                k = cgroup_attribute_apply(a, b);
                if (r == 0)
                        r = k;
        }

        return r;
}

CGroupAttribute *cgroup_attribute_find_list(CGroupAttribute *first, const char *controller, const char *name) {
        CGroupAttribute *a;

        assert(controller);
        assert(name);

        LIST_FOREACH(by_unit, a, first)
                if (streq(a->controller, controller) &&
                    streq(a->name, name))
                        return a;

        return NULL;
}

static void cgroup_attribute_free(CGroupAttribute *a) {
        assert(a);

        free(a->controller);
        free(a->name);
        free(a->value);
        free(a);
}

void cgroup_attribute_free_list(CGroupAttribute *first) {
        CGroupAttribute *a, *n;

        LIST_FOREACH_SAFE(by_unit, a, n, first)
                cgroup_attribute_free(a);
}
