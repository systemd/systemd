/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <stddef.h>

#include "util.h"
#include "uid-range.h"

int main(int argc, char *argv[]) {
        _cleanup_free_ UidRange *p = NULL;
        unsigned n = 0;
        uid_t search;

        assert_se(uid_range_add_str(&p, &n, "500-999") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 500);
        assert_se(p[0].nr == 500);

        assert_se(!uid_range_contains(p, n, 499));
        assert_se(uid_range_contains(p, n, 500));
        assert_se(uid_range_contains(p, n, 999));
        assert_se(!uid_range_contains(p, n, 1000));

        search = UID_INVALID;
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 999);
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 998);
        search = 501;
        assert_se(uid_range_next_lower(p, n, &search));
        assert_se(search == 500);
        assert_se(uid_range_next_lower(p, n, &search) == -EBUSY);

        assert_se(uid_range_add_str(&p, &n, "1000") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 500);
        assert_se(p[0].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "30-40") >= 0);
        assert_se(n == 2);
        assert_se(p[0].start == 30);
        assert_se(p[0].nr == 11);
        assert_se(p[1].start == 500);
        assert_se(p[1].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "60-70") >= 0);
        assert_se(n == 3);
        assert_se(p[0].start == 30);
        assert_se(p[0].nr == 11);
        assert_se(p[1].start == 60);
        assert_se(p[1].nr == 11);
        assert_se(p[2].start == 500);
        assert_se(p[2].nr == 501);

        assert_se(uid_range_add_str(&p, &n, "20-2000") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1981);

        assert_se(uid_range_add_str(&p, &n, "2002") >= 0);
        assert_se(n == 2);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1981);
        assert_se(p[1].start == 2002);
        assert_se(p[1].nr == 1);

        assert_se(uid_range_add_str(&p, &n, "2001") >= 0);
        assert_se(n == 1);
        assert_se(p[0].start == 20);
        assert_se(p[0].nr == 1983);

        return 0;
}
