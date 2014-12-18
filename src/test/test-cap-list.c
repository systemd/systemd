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

#include "log.h"
#include "cap-list.h"
#include "capability.h"

int main(int argc, char *argv[]) {
        int i;

        assert_se(!capability_to_name(-1));
        assert_se(!capability_to_name(cap_last_cap()+1));

        for (i = 0; i <= (int) cap_last_cap(); i++) {
                const char *n;

                assert_se(n = capability_to_name(i));
                assert_se(capability_from_name(n) == i);
                printf("%s = %i\n", n, i);
        }

        assert_se(capability_from_name("asdfbsd") == -EINVAL);
        assert_se(capability_from_name("CAP_AUDIT_READ") == CAP_AUDIT_READ);
        assert_se(capability_from_name("cap_audit_read") == CAP_AUDIT_READ);
        assert_se(capability_from_name("cAp_aUdIt_rEAd") == CAP_AUDIT_READ);
        assert_se(capability_from_name("0") == 0);
        assert_se(capability_from_name("15") == 15);
        assert_se(capability_from_name("-1") == -EINVAL);

        for (i = 0; i <= (int) cap_last_cap(); i++) {
                _cleanup_cap_free_charp_ char *a = NULL;
                const char *b;
                unsigned u;

                assert_se(a = cap_to_name(i));

                /* quit the loop as soon as libcap starts returning
                 * numeric ids, formatted as strings */
                if (safe_atou(a, &u) >= 0)
                        break;

                assert_se(b = capability_to_name(i));

                printf("%s vs. %s\n", a, b);

                assert_se(strcasecmp(a, b) == 0);
        }

        return 0;
}
