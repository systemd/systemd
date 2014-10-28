/***
  This file is part of systemd

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <stdio.h>
#include <stdlib.h>

typedef const char* (*lookup_t)(int);
typedef int (*reverse_t)(const char*);

static inline void _test_table(const char *name,
                               lookup_t lookup,
                               reverse_t reverse,
                               int size,
                               bool sparse) {
        int i;

        for (i = -1; i < size + 1; i++) {
                const char* val = lookup(i);
                int rev;

                if (val)
                        rev = reverse(val);
                else
                        rev = reverse("--no-such--value----");

                printf("%s: %d → %s → %d\n", name, i, val, rev);
                assert_se(!(i >= 0 && i < size ?
                            sparse ? rev != i && rev != -1 : val == NULL || rev != i :
                            val != NULL || rev != -1));
        }
}

#define test_table(lower, upper) \
        _test_table(STRINGIFY(lower), lower##_to_string, lower##_from_string, _##upper##_MAX, false)

#define test_table_sparse(lower, upper) \
        _test_table(STRINGIFY(lower), lower##_to_string, lower##_from_string, _##upper##_MAX, true)
