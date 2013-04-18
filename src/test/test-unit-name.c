/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
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
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

#include "manager.h"
#include "unit.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "install.h"
#include "specifier.h"
#include "util.h"
#include "macro.h"

static void test_replacements(void) {
#define expect(pattern, repl, expected)                            \
        {                                                          \
                _cleanup_free_ char *t =                           \
                        unit_name_replace_instance(pattern, repl); \
                puts(t);                                           \
                assert(streq(t, expected));                        \
        }

        expect("foo@.service", "waldo", "foo@waldo.service");
        expect("foo@xyz.service", "waldo", "foo@waldo.service");
        expect("xyz", "waldo", "xyz");
        expect("", "waldo", "");
        expect("foo.service", "waldo", "foo.service");
        expect(".service", "waldo", ".service");
        expect("foo@", "waldo", "foo@waldo");
        expect("@bar", "waldo", "@waldo");

        puts("-------------------------------------------------");
#undef expect
#define expect(path, suffix, expected)                             \
        {                                                          \
                _cleanup_free_ char *k, *t =                       \
                        unit_name_from_path(path, suffix);         \
                puts(t);                                           \
                k = unit_name_to_path(t);                          \
                puts(k);                                           \
                assert(streq(k, expected ? expected : path));     \
        }

        expect("/waldo", ".mount", NULL);
        expect("/waldo/quuix", ".mount", NULL);
        expect("/waldo/quuix/", ".mount", "/waldo/quuix");
        expect("/", ".mount", NULL);
        expect("///", ".mount", "/");

        puts("-------------------------------------------------");
#undef expect
#define expect(pattern, path, suffix, expected)                         \
        {                                                               \
                _cleanup_free_ char *t =                                \
                        unit_name_from_path_instance(pattern, path, suffix); \
                puts(t);                                                \
                assert(streq(t, expected));                             \
        }

        expect("waldo", "/waldo", ".mount", "waldo@waldo.mount");
        expect("waldo", "/waldo////quuix////", ".mount", "waldo@waldo-quuix.mount");
        expect("waldo", "/", ".mount", "waldo@-.mount");
        expect("wa--ldo", "/--", ".mount", "wa--ldo@\\x2d\\x2d.mount");

        puts("-------------------------------------------------");
#undef expect
#define expect(pattern)                                                 \
        {                                                               \
                _cleanup_free_ char *k, *t;                             \
                assert_se(t = unit_name_mangle(pattern));               \
                assert_se(k = unit_name_mangle(t));                     \
                puts(t);                                                \
                assert_se(streq(t, k));                                 \
        }

        expect("/home");
        expect("/dev/sda");
        expect("üxknürz.service");
        expect("foobar-meh...waldi.service");
        expect("_____####----.....service");
        expect("_____##@;;;,,,##----.....service");
        expect("xxx@@@@/////\\\\\\\\\\yyy.service");

#undef expect
}

static int test_unit_printf(void) {
        Manager *m;
        Unit *u, *u2;
        int r;

        _cleanup_free_ char *mid, *bid, *host, *root_uid;
        struct passwd *root;

        assert_se((mid = specifier_machine_id('m', NULL, NULL)));
        assert_se((bid = specifier_boot_id('b', NULL, NULL)));
        assert_se((host = gethostname_malloc()));

        assert_se((root = getpwnam("root")));
        assert_se(asprintf(&root_uid, "%d", (int) root->pw_uid) > 0);

        r = manager_new(SYSTEMD_USER, &m);
        if (r == -EPERM) {
                puts("manager_new: Permission denied. Skipping test.");
                return EXIT_TEST_SKIP;
        }
        assert(r == 0);

#define expect(unit, pattern, expected)                                 \
        {                                                               \
                char *e;                                                \
                _cleanup_free_ char *t =                                \
                        unit_full_printf(unit, pattern);                \
                printf("result: %s\nexpect: %s\n", t, expected);        \
                if ((e = endswith(expected, "*")))                      \
                        assert(strncmp(t, e, e-expected));              \
                else                                                    \
                        assert(streq(t, expected));                     \
        }

        assert_se(setenv("USER", "root", 1) == 0);
        assert_se(setenv("HOME", "/root", 1) == 0);

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "blah.service") == 0);
        assert_se(unit_add_name(u, "blah.service") == 0);

        /* general tests */
        expect(u, "%%", "%");
        expect(u, "%%s", "%s");
        expect(u, "%", "");    // REALLY?

        /* normal unit */
        expect(u, "%n", "blah.service");
        expect(u, "%N", "blah");
        expect(u, "%p", "blah");
        expect(u, "%P", "blah");
        expect(u, "%i", "");
        expect(u, "%I", "");
        expect(u, "%u", root->pw_name);
        expect(u, "%U", root_uid);
        expect(u, "%h", root->pw_dir);
        expect(u, "%s", "/bin/sh");
        expect(u, "%m", mid);
        expect(u, "%b", bid);
        expect(u, "%H", host);
        expect(u, "%t", "/run/user/*");

        /* templated */
        assert_se(u2 = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u2, "blah@foo-foo.service") == 0);
        assert_se(unit_add_name(u2, "blah@foo-foo.service") == 0);

        expect(u2, "%n", "blah@foo-foo.service");
        expect(u2, "%N", "blah@foo-foo");
        expect(u2, "%p", "blah");
        expect(u2, "%P", "blah");
        expect(u2, "%i", "foo-foo");
        expect(u2, "%I", "foo/foo");
        expect(u2, "%u", root->pw_name);
        expect(u2, "%U", root_uid);
        expect(u2, "%h", root->pw_dir);
        expect(u2, "%s", "/bin/sh");
        expect(u2, "%m", mid);
        expect(u2, "%b", bid);
        expect(u2, "%H", host);
        expect(u2, "%t", "/run/user/*");

        return 0;
}

int main(int argc, char* argv[]) {
        test_replacements();
        return test_unit_printf();
}
