/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
  Copyright 2013 Zbigniew Jędrzejewski-Szmek
  Copyright 2014 Ronny Chevalier

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

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "manager.h"
#include "path-util.h"
#include "specifier.h"
#include "string-util.h"
#include "test-helper.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"
#include "util.h"

static void test_unit_name_is_valid(void) {
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_ANY));
        assert_se(unit_name_is_valid("foo.service", UNIT_NAME_PLAIN));
        assert_se(!unit_name_is_valid("foo.service", UNIT_NAME_INSTANCE));
        assert_se(!unit_name_is_valid("foo.service", UNIT_NAME_TEMPLATE));
        assert_se(!unit_name_is_valid("foo.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE));

        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("foo@bar.service", UNIT_NAME_PLAIN));
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_INSTANCE));
        assert_se(!unit_name_is_valid("foo@bar.service", UNIT_NAME_TEMPLATE));
        assert_se(unit_name_is_valid("foo@bar.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE));

        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("foo@.service", UNIT_NAME_PLAIN));
        assert_se(!unit_name_is_valid("foo@.service", UNIT_NAME_INSTANCE));
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_TEMPLATE));
        assert_se(unit_name_is_valid("foo@.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE));

        assert_se(!unit_name_is_valid(".service", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("foo.waldo", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("@.service", UNIT_NAME_ANY));
        assert_se(!unit_name_is_valid("@piep.service", UNIT_NAME_ANY));
}

static void test_u_n_r_i_one(const char *pattern, const char *repl, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;
        assert_se(unit_name_replace_instance(pattern, repl, &t) == ret);
        puts(strna(t));
        assert_se(streq_ptr(t, expected));
}

static void test_u_n_r_i(void) {
        puts("-------------------------------------------------");
        test_u_n_r_i_one("foo@.service", "waldo", "foo@waldo.service", 0);
        test_u_n_r_i_one("foo@xyz.service", "waldo", "foo@waldo.service", 0);
        test_u_n_r_i_one("xyz", "waldo", NULL, -EINVAL);
        test_u_n_r_i_one("", "waldo", NULL, -EINVAL);
        test_u_n_r_i_one("foo.service", "waldo", NULL, -EINVAL);
        test_u_n_r_i_one(".service", "waldo", NULL, -EINVAL);
        test_u_n_r_i_one("foo@", "waldo", NULL, -EINVAL);
        test_u_n_r_i_one("@bar", "waldo", NULL, -EINVAL);
}

static void test_u_n_f_p_one(const char *path, const char *suffix, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;

        assert_se(unit_name_from_path(path, suffix, &t) == ret);
        puts(strna(t));
        assert_se(streq_ptr(t, expected));

        if (t) {
                _cleanup_free_ char *k = NULL;
                assert_se(unit_name_to_path(t, &k) == 0);
                puts(strna(k));
                assert_se(path_equal(k, isempty(path) ? "/" : path));
        }
}

static void test_u_n_f_p(void) {
        puts("-------------------------------------------------");
        test_u_n_f_p_one("/waldo", ".mount", "waldo.mount", 0);
        test_u_n_f_p_one("/waldo/quuix", ".mount", "waldo-quuix.mount", 0);
        test_u_n_f_p_one("/waldo/quuix/", ".mount", "waldo-quuix.mount", 0);
        test_u_n_f_p_one("", ".mount", "-.mount", 0);
        test_u_n_f_p_one("/", ".mount", "-.mount", 0);
        test_u_n_f_p_one("///", ".mount", "-.mount", 0);
        test_u_n_f_p_one("/foo/../bar", ".mount", NULL, -EINVAL);
        test_u_n_f_p_one("/foo/./bar", ".mount", NULL, -EINVAL);
}

static void test_u_n_f_p_i_one(const char *pattern, const char *path, const char *suffix, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;

        assert_se(unit_name_from_path_instance(pattern, path, suffix, &t) == ret);
        puts(strna(t));
        assert_se(streq_ptr(t, expected));

        if (t) {
                _cleanup_free_ char *k = NULL, *v = NULL;

                assert_se(unit_name_to_instance(t, &k) > 0);
                assert_se(unit_name_path_unescape(k, &v) == 0);
                assert_se(path_equal(v, isempty(path) ? "/" : path));
        }
}

static void test_u_n_f_p_i(void) {
        puts("-------------------------------------------------");

        test_u_n_f_p_i_one("waldo", "/waldo", ".mount", "waldo@waldo.mount", 0);
        test_u_n_f_p_i_one("waldo", "/waldo////quuix////", ".mount", "waldo@waldo-quuix.mount", 0);
        test_u_n_f_p_i_one("waldo", "/", ".mount", "waldo@-.mount", 0);
        test_u_n_f_p_i_one("waldo", "", ".mount", "waldo@-.mount", 0);
        test_u_n_f_p_i_one("waldo", "///", ".mount", "waldo@-.mount", 0);
        test_u_n_f_p_i_one("waldo", "..", ".mount", NULL, -EINVAL);
        test_u_n_f_p_i_one("waldo", "/foo", ".waldi", NULL, -EINVAL);
        test_u_n_f_p_i_one("wa--ldo", "/--", ".mount", "wa--ldo@\\x2d\\x2d.mount", 0);
}

static void test_u_n_t_p_one(const char *unit, const char *path, int ret) {
        _cleanup_free_ char *p = NULL;

        assert_se(unit_name_to_path(unit, &p) == ret);
        assert_se(streq_ptr(path, p));
}

static void test_u_n_t_p(void) {
        test_u_n_t_p_one("home.mount", "/home", 0);
        test_u_n_t_p_one("home-lennart.mount", "/home/lennart", 0);
        test_u_n_t_p_one("home-lennart-.mount", NULL, -EINVAL);
        test_u_n_t_p_one("-home-lennart.mount", NULL, -EINVAL);
        test_u_n_t_p_one("-home--lennart.mount", NULL, -EINVAL);
        test_u_n_t_p_one("home-..-lennart.mount", NULL, -EINVAL);
        test_u_n_t_p_one("", NULL, -EINVAL);
        test_u_n_t_p_one("home/foo", NULL, -EINVAL);
}

static void test_u_n_m_one(const char *pattern, const char *expect, int ret) {
        _cleanup_free_ char *t = NULL;

        assert_se(unit_name_mangle(pattern, UNIT_NAME_NOGLOB, &t) == ret);
        puts(strna(t));
        assert_se(streq_ptr(t, expect));

        if (t) {
                _cleanup_free_ char *k = NULL;

                assert_se(unit_name_is_valid(t, UNIT_NAME_ANY));

                assert_se(unit_name_mangle(t, UNIT_NAME_NOGLOB, &k) == 0);
                assert_se(streq_ptr(t, k));
        }
}

static void test_u_n_m(void) {
        puts("-------------------------------------------------");
        test_u_n_m_one("foo.service", "foo.service", 0);
        test_u_n_m_one("/home", "home.mount", 1);
        test_u_n_m_one("/dev/sda", "dev-sda.device", 1);
        test_u_n_m_one("üxknürz.service", "\\xc3\\xbcxkn\\xc3\\xbcrz.service", 1);
        test_u_n_m_one("foobar-meh...waldi.service", "foobar-meh...waldi.service", 0);
        test_u_n_m_one("_____####----.....service", "_____\\x23\\x23\\x23\\x23----.....service", 1);
        test_u_n_m_one("_____##@;;;,,,##----.....service", "_____\\x23\\x23@\\x3b\\x3b\\x3b\\x2c\\x2c\\x2c\\x23\\x23----.....service", 1);
        test_u_n_m_one("xxx@@@@/////\\\\\\\\\\yyy.service", "xxx@@@@-----\\\\\\\\\\yyy.service", 1);
        test_u_n_m_one("", NULL, -EINVAL);
}

static int test_unit_printf(void) {
        Manager *m = NULL;
        Unit *u, *u2;
        int r;

        _cleanup_free_ char *mid = NULL, *bid = NULL, *host = NULL, *uid = NULL, *user = NULL, *shell = NULL, *home = NULL;

        assert_se(specifier_machine_id('m', NULL, NULL, &mid) >= 0 && mid);
        assert_se(specifier_boot_id('b', NULL, NULL, &bid) >= 0 && bid);
        assert_se(host = gethostname_malloc());
        assert_se(user = getusername_malloc());
        assert_se(asprintf(&uid, UID_FMT, getuid()));
        assert_se(get_home_dir(&home) >= 0);
        assert_se(get_shell(&shell) >= 0);

        r = manager_new(MANAGER_USER, true, &m);
        if (r == -EPERM || r == -EACCES || r == -EADDRINUSE) {
                puts("manager_new: Permission denied. Skipping test.");
                return EXIT_TEST_SKIP;
        }
        assert_se(r == 0);

#define expect(unit, pattern, expected)                                 \
        {                                                               \
                char *e;                                                \
                _cleanup_free_ char *t = NULL;                          \
                assert_se(unit_full_printf(unit, pattern, &t) >= 0);    \
                printf("result: %s\nexpect: %s\n", t, expected);        \
                if ((e = endswith(expected, "*")))                      \
                        assert_se(strncmp(t, e, e-expected));              \
                else                                                    \
                        assert_se(streq(t, expected));                     \
        }

        assert_se(setenv("XDG_RUNTIME_DIR", "/run/user/1/", 1) == 0);

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "blah.service") == 0);
        assert_se(unit_add_name(u, "blah.service") == 0);

        /* general tests */
        expect(u, "%%", "%");
        expect(u, "%%s", "%s");
        expect(u, "%", "");    // REALLY?

        /* normal unit */
        expect(u, "%n", "blah.service");
        expect(u, "%f", "/blah");
        expect(u, "%N", "blah");
        expect(u, "%p", "blah");
        expect(u, "%P", "blah");
        expect(u, "%i", "");
        expect(u, "%u", user);
        expect(u, "%U", uid);
        expect(u, "%h", home);
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
        expect(u2, "%f", "/foo/foo");
        expect(u2, "%p", "blah");
        expect(u2, "%P", "blah");
        expect(u2, "%i", "foo-foo");
        expect(u2, "%I", "foo/foo");
        expect(u2, "%u", user);
        expect(u2, "%U", uid);
        expect(u2, "%h", home);
        expect(u2, "%m", mid);
        expect(u2, "%b", bid);
        expect(u2, "%H", host);
        expect(u2, "%t", "/run/user/*");

        manager_free(m);
#undef expect

        return 0;
}

static void test_unit_instance_is_valid(void) {
        assert_se(unit_instance_is_valid("fooBar"));
        assert_se(unit_instance_is_valid("foo-bar"));
        assert_se(unit_instance_is_valid("foo.stUff"));
        assert_se(unit_instance_is_valid("fOo123.stuff"));
        assert_se(unit_instance_is_valid("@f_oo123.Stuff"));

        assert_se(!unit_instance_is_valid("$¢£"));
        assert_se(!unit_instance_is_valid(""));
        assert_se(!unit_instance_is_valid("foo bar"));
        assert_se(!unit_instance_is_valid("foo/bar"));
}

static void test_unit_prefix_is_valid(void) {
        assert_se(unit_prefix_is_valid("fooBar"));
        assert_se(unit_prefix_is_valid("foo-bar"));
        assert_se(unit_prefix_is_valid("foo.stUff"));
        assert_se(unit_prefix_is_valid("fOo123.stuff"));
        assert_se(unit_prefix_is_valid("foo123.Stuff"));

        assert_se(!unit_prefix_is_valid("$¢£"));
        assert_se(!unit_prefix_is_valid(""));
        assert_se(!unit_prefix_is_valid("foo bar"));
        assert_se(!unit_prefix_is_valid("foo/bar"));
        assert_se(!unit_prefix_is_valid("@foo-bar"));
}

static void test_unit_name_change_suffix(void) {
        char *t;

        assert_se(unit_name_change_suffix("foo.mount", ".service", &t) == 0);
        assert_se(streq(t, "foo.service"));
        free(t);

        assert_se(unit_name_change_suffix("foo@stuff.service", ".socket", &t) == 0);
        assert_se(streq(t, "foo@stuff.socket"));
        free(t);
}

static void test_unit_name_build(void) {
        char *t;

        assert_se(unit_name_build("foo", "bar", ".service", &t) == 0);
        assert_se(streq(t, "foo@bar.service"));
        free(t);

        assert_se(unit_name_build("fo0-stUff_b", "bar", ".mount", &t) == 0);
        assert_se(streq(t, "fo0-stUff_b@bar.mount"));
        free(t);

        assert_se(unit_name_build("foo", NULL, ".service", &t) == 0);
        assert_se(streq(t, "foo.service"));
        free(t);
}

static void test_slice_name_is_valid(void) {
        assert_se(slice_name_is_valid("-.slice"));
        assert_se(slice_name_is_valid("foo.slice"));
        assert_se(slice_name_is_valid("foo-bar.slice"));
        assert_se(slice_name_is_valid("foo-bar-baz.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz.slice"));
        assert_se(!slice_name_is_valid("foo-bar-baz-.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz-.slice"));
        assert_se(!slice_name_is_valid("foo-bar--baz.slice"));
        assert_se(!slice_name_is_valid("foo--bar--baz.slice"));
        assert_se(!slice_name_is_valid(".slice"));
        assert_se(!slice_name_is_valid(""));
        assert_se(!slice_name_is_valid("foo.service"));
}

static void test_build_subslice(void) {
        char *a;
        char *b;

        assert_se(slice_build_subslice("-.slice", "foo", &a) >= 0);
        assert_se(slice_build_subslice(a, "bar", &b) >= 0);
        free(a);
        assert_se(slice_build_subslice(b, "barfoo", &a) >= 0);
        free(b);
        assert_se(slice_build_subslice(a, "foobar", &b) >= 0);
        free(a);
        assert_se(streq(b, "foo-bar-barfoo-foobar.slice"));
        free(b);

        assert_se(slice_build_subslice("foo.service", "bar", &a) < 0);
        assert_se(slice_build_subslice("foo", "bar", &a) < 0);
}

static void test_build_parent_slice_one(const char *name, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(slice_build_parent_slice(name, &s) == ret);
        assert_se(streq_ptr(s, expect));
}

static void test_build_parent_slice(void) {
        test_build_parent_slice_one("-.slice", NULL, 0);
        test_build_parent_slice_one("foo.slice", "-.slice", 1);
        test_build_parent_slice_one("foo-bar.slice", "foo.slice", 1);
        test_build_parent_slice_one("foo-bar-baz.slice", "foo-bar.slice", 1);
        test_build_parent_slice_one("foo-bar--baz.slice", NULL, -EINVAL);
        test_build_parent_slice_one("-foo-bar.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar-.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar.service", NULL, -EINVAL);
        test_build_parent_slice_one(".slice", NULL, -EINVAL);
}

static void test_unit_name_to_instance(void) {
        char *instance;
        int r;

        r = unit_name_to_instance("foo@bar.service", &instance);
        assert_se(r >= 0);
        assert_se(streq(instance, "bar"));
        free(instance);

        r = unit_name_to_instance("foo@.service", &instance);
        assert_se(r >= 0);
        assert_se(streq(instance, ""));
        free(instance);

        r = unit_name_to_instance("fo0-stUff_b@b.service", &instance);
        assert_se(r >= 0);
        assert_se(streq(instance, "b"));
        free(instance);

        r = unit_name_to_instance("foo.service", &instance);
        assert_se(r == 0);
        assert_se(!instance);

        r = unit_name_to_instance("fooj@unk", &instance);
        assert_se(r < 0);

        r = unit_name_to_instance("foo@", &instance);
        assert_se(r < 0);
}

static void test_unit_name_escape(void) {
        _cleanup_free_ char *r;

        r = unit_name_escape("ab+-c.a/bc@foo.service");
        assert_se(r);
        assert_se(streq(r, "ab\\x2b\\x2dc.a-bc\\x40foo.service"));
}


static void test_u_n_t_one(const char *name, const char *expected, int ret) {
        _cleanup_free_ char *f = NULL;

        assert_se(unit_name_template(name, &f) == ret);
        printf("got: %s, expected: %s\n", strna(f), strna(expected));
        assert_se(streq_ptr(f, expected));
}

static void test_unit_name_template(void) {
        test_u_n_t_one("foo@bar.service", "foo@.service", 0);
        test_u_n_t_one("foo.mount", NULL, -EINVAL);
}

static void test_unit_name_path_unescape_one(const char *name, const char *path, int ret) {
        _cleanup_free_ char *p = NULL;

        assert_se(unit_name_path_unescape(name, &p) == ret);
        assert_se(streq_ptr(path, p));
}

static void test_unit_name_path_unescape(void) {

        test_unit_name_path_unescape_one("foo", "/foo", 0);
        test_unit_name_path_unescape_one("foo-bar", "/foo/bar", 0);
        test_unit_name_path_unescape_one("foo-.bar", "/foo/.bar", 0);
        test_unit_name_path_unescape_one("foo-bar-baz", "/foo/bar/baz", 0);
        test_unit_name_path_unescape_one("-", "/", 0);
        test_unit_name_path_unescape_one("--", NULL, -EINVAL);
        test_unit_name_path_unescape_one("-foo-bar", NULL, -EINVAL);
        test_unit_name_path_unescape_one("foo--bar", NULL, -EINVAL);
        test_unit_name_path_unescape_one("foo-bar-", NULL, -EINVAL);
        test_unit_name_path_unescape_one(".-bar", NULL, -EINVAL);
        test_unit_name_path_unescape_one("foo-..", NULL, -EINVAL);
        test_unit_name_path_unescape_one("", NULL, -EINVAL);
}

int main(int argc, char* argv[]) {
        int rc = 0;
        test_unit_name_is_valid();
        test_u_n_r_i();
        test_u_n_f_p();
        test_u_n_f_p_i();
        test_u_n_m();
        test_u_n_t_p();
        TEST_REQ_RUNNING_SYSTEMD(rc = test_unit_printf());
        test_unit_instance_is_valid();
        test_unit_prefix_is_valid();
        test_unit_name_change_suffix();
        test_unit_name_build();
        test_slice_name_is_valid();
        test_build_subslice();
        test_build_parent_slice();
        test_unit_name_to_instance();
        test_unit_name_escape();
        test_unit_name_template();
        test_unit_name_path_unescape();

        return rc;
}
