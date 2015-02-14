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

#include "util.h"
#include "fileio.h"
#include "cap-list.h"
#include "capability.h"
#include <sys/prctl.h>

/* verify the capability parser */
static void test_cap_list(void) {
        int i;

        assert_se(!capability_to_name(-1));
        assert_se(!capability_to_name(capability_list_length()));

        for (i = 0; i < capability_list_length(); i++) {
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

        for (i = 0; i < capability_list_length(); i++) {
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
}

/* verify cap_last_cap() against /proc/sys/kernel/cap_last_cap */
static void test_last_cap_file(void) {
        _cleanup_free_ char *content = NULL;
        unsigned long val = 0;
        int r;

        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        assert_se(r >= 0);

        r = safe_atolu(content, &val);
        assert_se(r >= 0);
        assert_se(val != 0);
        assert_se(val == cap_last_cap());
}

/* verify cap_last_cap() against syscall probing */
static void test_last_cap_probe(void) {
        unsigned long p = (unsigned long)CAP_LAST_CAP;

        if (prctl(PR_CAPBSET_READ, p) < 0) {
                for (p--; p > 0; p --)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;
        } else {
                for (;; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        assert_se(p != 0);
        assert_se(p == cap_last_cap());
}

int main(int argc, char *argv[]) {
        test_cap_list();
        test_last_cap_file();
        test_last_cap_probe();

        return 0;
}
