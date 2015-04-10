/***
  This file is part of systemd

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "set.h"

static void test_set_steal_first(void) {
        _cleanup_set_free_ Set *m = NULL;
        int seen[3] = {};
        char *val;

        m = set_new(&string_hash_ops);
        assert_se(m);

        assert_se(set_put(m, (void*) "1") == 1);
        assert_se(set_put(m, (void*) "22") == 1);
        assert_se(set_put(m, (void*) "333") == 1);

        while ((val = set_steal_first(m)))
                seen[strlen(val) - 1]++;

        assert_se(seen[0] == 1 && seen[1] == 1 && seen[2] == 1);

        assert_se(set_isempty(m));
}

static void test_set_put(void) {
        _cleanup_set_free_ Set *m = NULL;

        m = set_new(&string_hash_ops);
        assert_se(m);

        assert_se(set_put(m, (void*) "1") == 1);
        assert_se(set_put(m, (void*) "22") == 1);
        assert_se(set_put(m, (void*) "333") == 1);
        assert_se(set_put(m, (void*) "333") == 0);
        assert_se(set_remove(m, (void*) "333"));
        assert_se(set_put(m, (void*) "333") == 1);
        assert_se(set_put(m, (void*) "333") == 0);
        assert_se(set_put(m, (void*) "22") == 0);
}

int main(int argc, const char *argv[]) {
        test_set_steal_first();
        test_set_put();

        return 0;
}
