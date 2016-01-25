/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include "ordered-set.h"
#include "strv.h"

int ordered_set_consume(OrderedSet *s, void *p) {
        int r;

        r = ordered_set_put(s, p);
        if (r <= 0)
                free(p);

        return r;
}

int ordered_set_put_strdup(OrderedSet *s, const char *p) {
        char *c;
        int r;

        assert(s);
        assert(p);

        c = strdup(p);
        if (!c)
                return -ENOMEM;

        r = ordered_set_consume(s, c);
        if (r == -EEXIST)
                return 0;

        return r;
}

int ordered_set_put_strdupv(OrderedSet *s, char **l) {
        int n = 0, r;
        char **i;

        STRV_FOREACH(i, l) {
                r = ordered_set_put_strdup(s, *i);
                if (r < 0)
                        return r;

                n += r;
        }

        return n;
}
