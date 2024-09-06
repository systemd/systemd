/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "all-units.h"
#include "glob-util.h"
#include "format-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "manager.h"
#include "path-util.h"
#include "rm-rf.h"
#include "special.h"
#include "specifier.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "unit-printf.h"
#include "unit.h"
#include "user-util.h"

static char *runtime_dir = NULL;

STATIC_DESTRUCTOR_REGISTER(runtime_dir, rm_rf_physical_and_freep);

static void test_unit_name_is_valid_one(const char *name, UnitNameFlags flags, bool expected) {
        log_info("%s ( %s%s%s ): %s",
                 name,
                 (flags & UNIT_NAME_PLAIN) ? "plain" : "",
                 (flags & UNIT_NAME_INSTANCE) ? " instance" : "",
                 (flags & UNIT_NAME_TEMPLATE) ? " template" : "",
                 yes_no(expected));
        assert_se(unit_name_is_valid(name, flags) == expected);
}

TEST(unit_name_is_valid) {
        test_unit_name_is_valid_one("foo.service", UNIT_NAME_ANY, true);
        test_unit_name_is_valid_one("foo.service", UNIT_NAME_PLAIN, true);
        test_unit_name_is_valid_one("foo.service", UNIT_NAME_INSTANCE, false);
        test_unit_name_is_valid_one("foo.service", UNIT_NAME_TEMPLATE, false);
        test_unit_name_is_valid_one("foo.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE, false);

        test_unit_name_is_valid_one("foo@bar.service", UNIT_NAME_ANY, true);
        test_unit_name_is_valid_one("foo@bar.service", UNIT_NAME_PLAIN, false);
        test_unit_name_is_valid_one("foo@bar.service", UNIT_NAME_INSTANCE, true);
        test_unit_name_is_valid_one("foo@bar.service", UNIT_NAME_TEMPLATE, false);
        test_unit_name_is_valid_one("foo@bar.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE, true);

        test_unit_name_is_valid_one("foo@bar@bar.service", UNIT_NAME_ANY, true);
        test_unit_name_is_valid_one("foo@bar@bar.service", UNIT_NAME_PLAIN, false);
        test_unit_name_is_valid_one("foo@bar@bar.service", UNIT_NAME_INSTANCE, true);
        test_unit_name_is_valid_one("foo@bar@bar.service", UNIT_NAME_TEMPLATE, false);
        test_unit_name_is_valid_one("foo@bar@bar.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE, true);

        test_unit_name_is_valid_one("foo@.service", UNIT_NAME_ANY, true);
        test_unit_name_is_valid_one("foo@.service", UNIT_NAME_PLAIN, false);
        test_unit_name_is_valid_one("foo@.service", UNIT_NAME_INSTANCE, false);
        test_unit_name_is_valid_one("foo@.service", UNIT_NAME_TEMPLATE, true);
        test_unit_name_is_valid_one("foo@.service", UNIT_NAME_INSTANCE|UNIT_NAME_TEMPLATE, true);
        test_unit_name_is_valid_one(".test.service", UNIT_NAME_PLAIN, true);
        test_unit_name_is_valid_one(".test@.service", UNIT_NAME_TEMPLATE, true);
        test_unit_name_is_valid_one("_strange::::.service", UNIT_NAME_ANY, true);

        test_unit_name_is_valid_one(".service", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("foo.waldo", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("@.service", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("@piep.service", UNIT_NAME_ANY, false);

        test_unit_name_is_valid_one("user@1000.slice", UNIT_NAME_ANY, true);
        test_unit_name_is_valid_one("user@1000.slice", UNIT_NAME_INSTANCE, true);
        test_unit_name_is_valid_one("user@1000.slice", UNIT_NAME_TEMPLATE, false);

        test_unit_name_is_valid_one("foo@%i.service", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("foo@%i.service", UNIT_NAME_INSTANCE, false);
        test_unit_name_is_valid_one("foo@%%i.service", UNIT_NAME_INSTANCE, false);
        test_unit_name_is_valid_one("foo@%%i%f.service", UNIT_NAME_INSTANCE, false);
        test_unit_name_is_valid_one("foo@%F.service", UNIT_NAME_INSTANCE, false);

        test_unit_name_is_valid_one("foo.target.wants/plain.service", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("foo.target.conf/foo.conf", UNIT_NAME_ANY, false);
        test_unit_name_is_valid_one("foo.target.requires/plain.socket", UNIT_NAME_ANY, false);
}

static void test_unit_name_replace_instance_one(const char *pattern, const char *repl, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;
        assert_se(unit_name_replace_instance(pattern, repl, &t) == ret);
        puts(strna(t));
        ASSERT_STREQ(t, expected);
}

TEST(unit_name_replace_instance) {
        test_unit_name_replace_instance_one("foo@.service", "waldo", "foo@waldo.service", 0);
        test_unit_name_replace_instance_one("foo@xyz.service", "waldo", "foo@waldo.service", 0);
        test_unit_name_replace_instance_one("xyz", "waldo", NULL, -EINVAL);
        test_unit_name_replace_instance_one("", "waldo", NULL, -EINVAL);
        test_unit_name_replace_instance_one("foo.service", "waldo", NULL, -EINVAL);
        test_unit_name_replace_instance_one(".service", "waldo", NULL, -EINVAL);
        test_unit_name_replace_instance_one("foo@", "waldo", NULL, -EINVAL);
        test_unit_name_replace_instance_one("@bar", "waldo", NULL, -EINVAL);
}

static void test_unit_name_from_path_one(const char *path, const char *suffix, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert_se(unit_name_from_path(path, suffix, &t) == ret);
        puts(strna(t));
        ASSERT_STREQ(t, expected);

        if (t) {
                _cleanup_free_ char *k = NULL;

                /* We don't support converting hashed unit names back to paths */
                r = unit_name_to_path(t, &k);
                if (r == -ENAMETOOLONG)
                        return;
                assert(r == 0);

                puts(strna(k));
                assert_se(path_equal(k, empty_to_root(path)));
        }
}

TEST(unit_name_is_hashed) {
        assert_se(!unit_name_is_hashed(""));
        assert_se(!unit_name_is_hashed("foo@bar.service"));
        assert_se(!unit_name_is_hashed("foo@.service"));
        assert_se(unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_7736d9ed33c2ec55.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_7736D9ED33C2EC55.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!7736d9ed33c2ec55.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_7736d9gd33c2ec55.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_2103e1466b87f7f7@waldo.mount"));
        assert_se(!unit_name_is_hashed("waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_2103e1466b87f7f7@.mount"));
}

TEST(unit_name_from_path) {
        test_unit_name_from_path_one("/waldo", ".mount", "waldo.mount", 0);
        test_unit_name_from_path_one("/waldo/quuix", ".mount", "waldo-quuix.mount", 0);
        test_unit_name_from_path_one("/waldo/quuix/", ".mount", "waldo-quuix.mount", 0);
        test_unit_name_from_path_one("", ".mount", "-.mount", 0);
        test_unit_name_from_path_one("/", ".mount", "-.mount", 0);
        test_unit_name_from_path_one("///", ".mount", "-.mount", 0);
        test_unit_name_from_path_one("/foo/../bar", ".mount", NULL, -EINVAL);
        test_unit_name_from_path_one("/foo/./bar", ".mount", "foo-bar.mount", 0);
        test_unit_name_from_path_one("/waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ".mount",
                                     "waldoaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_7736d9ed33c2ec55.mount", 0);
}

static void test_unit_name_from_path_instance_one(const char *pattern, const char *path, const char *suffix, const char *expected, int ret) {
        _cleanup_free_ char *t = NULL;

        assert_se(unit_name_from_path_instance(pattern, path, suffix, &t) == ret);
        puts(strna(t));
        ASSERT_STREQ(t, expected);

        if (t) {
                _cleanup_free_ char *k = NULL, *v = NULL;

                assert_se(unit_name_to_instance(t, &k) > 0);
                assert_se(unit_name_path_unescape(k, &v) == 0);
                assert_se(path_equal(v, empty_to_root(path)));
        }
}

TEST(unit_name_from_path_instance) {
        test_unit_name_from_path_instance_one("waldo", "/waldo", ".mount", "waldo@waldo.mount", 0);
        test_unit_name_from_path_instance_one("waldo", "/waldo////quuix////", ".mount", "waldo@waldo-quuix.mount", 0);
        test_unit_name_from_path_instance_one("waldo", "/", ".mount", "waldo@-.mount", 0);
        test_unit_name_from_path_instance_one("waldo", "", ".mount", "waldo@-.mount", 0);
        test_unit_name_from_path_instance_one("waldo", "///", ".mount", "waldo@-.mount", 0);
        test_unit_name_from_path_instance_one("waldo", "..", ".mount", NULL, -EINVAL);
        test_unit_name_from_path_instance_one("waldo", "/foo", ".waldi", NULL, -EINVAL);
        test_unit_name_from_path_instance_one("wa--ldo", "/--", ".mount", "wa--ldo@\\x2d\\x2d.mount", 0);
}

static void test_unit_name_to_path_one(const char *unit, const char *path, int ret) {
        _cleanup_free_ char *p = NULL;

        assert_se(unit_name_to_path(unit, &p) == ret);
        ASSERT_STREQ(path, p);
}

TEST(unit_name_to_path) {
        test_unit_name_to_path_one("home.mount", "/home", 0);
        test_unit_name_to_path_one("home-lennart.mount", "/home/lennart", 0);
        test_unit_name_to_path_one("home-lennart-.mount", NULL, -EINVAL);
        test_unit_name_to_path_one("-home-lennart.mount", NULL, -EINVAL);
        test_unit_name_to_path_one("-home--lennart.mount", NULL, -EINVAL);
        test_unit_name_to_path_one("home-..-lennart.mount", NULL, -EINVAL);
        test_unit_name_to_path_one("", NULL, -EINVAL);
        test_unit_name_to_path_one("home/foo", NULL, -EINVAL);
}

static void test_unit_name_mangle_one(bool allow_globs, const char *pattern, const char *expect, int ret) {
        _cleanup_free_ char *t = NULL;
        int r;

        r = unit_name_mangle(pattern, (allow_globs * UNIT_NAME_MANGLE_GLOB) | UNIT_NAME_MANGLE_WARN, &t);
        log_debug("%s: %s -> %d, %s", __func__, pattern, r, strnull(t));

        assert_se(r == ret);
        puts(strna(t));
        ASSERT_STREQ(t, expect);

        if (t) {
                _cleanup_free_ char *k = NULL;

                assert_se(unit_name_is_valid(t, UNIT_NAME_ANY) ||
                          (allow_globs && string_is_glob(t)));

                assert_se(unit_name_mangle(t, (allow_globs * UNIT_NAME_MANGLE_GLOB) | UNIT_NAME_MANGLE_WARN, &k) == 0);
                ASSERT_STREQ(t, k);
        }
}

TEST(unit_name_mangle) {
        test_unit_name_mangle_one(false, "foo.service", "foo.service", 0);
        test_unit_name_mangle_one(false, "/home", "home.mount", 1);
        test_unit_name_mangle_one(false, "/dev/sda", "dev-sda.device", 1);
        test_unit_name_mangle_one(false, "üxknürz.service", "\\xc3\\xbcxkn\\xc3\\xbcrz.service", 1);
        test_unit_name_mangle_one(false, "foobar-meh...waldi.service", "foobar-meh...waldi.service", 0);
        test_unit_name_mangle_one(false, "_____####----.....service", "_____\\x23\\x23\\x23\\x23----.....service", 1);
        test_unit_name_mangle_one(false, "_____##@;;;,,,##----.....service", "_____\\x23\\x23@\\x3b\\x3b\\x3b\\x2c\\x2c\\x2c\\x23\\x23----.....service", 1);
        test_unit_name_mangle_one(false, "xxx@@@@/////\\\\\\\\\\yyy.service", "xxx@@@@-----\\\\\\\\\\yyy.service", 1);
        test_unit_name_mangle_one(false, "", NULL, -EINVAL);

        test_unit_name_mangle_one(true, "foo.service", "foo.service", 0);
        test_unit_name_mangle_one(true, "foo", "foo.service", 1);
        test_unit_name_mangle_one(true, "foo*", "foo*", 0);
        test_unit_name_mangle_one(true, "ü*", "\\xc3\\xbc*", 1);
}

static void test_unit_name_mangle_with_suffix_one(const char *arg, int expected, const char *expected_name) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = unit_name_mangle_with_suffix(arg, NULL, 0, ".service", &s);
        log_debug("%s: %s -> %d, %s", __func__, arg, r, strnull(s));

        assert_se(r == expected);
        ASSERT_STREQ(s, expected_name);
}

TEST(unit_name_mangle_with_suffix) {
        test_unit_name_mangle_with_suffix_one("", -EINVAL, NULL);

        test_unit_name_mangle_with_suffix_one("/dev", 1, "dev.mount");
        test_unit_name_mangle_with_suffix_one("/../dev", 1, "dev.mount");
        test_unit_name_mangle_with_suffix_one("/../dev/.", 1, "dev.mount");
        /* We don't skip the last '..', and it makes this an invalid device or mount name */
        test_unit_name_mangle_with_suffix_one("/.././dev/..", 1, "-..-.-dev-...service");
        test_unit_name_mangle_with_suffix_one("/.././dev", 1, "dev.mount");
        test_unit_name_mangle_with_suffix_one("/./.././../dev/", 1, "dev.mount");

        test_unit_name_mangle_with_suffix_one("/dev/sda", 1, "dev-sda.device");
        test_unit_name_mangle_with_suffix_one("/dev/sda5", 1, "dev-sda5.device");

        test_unit_name_mangle_with_suffix_one("/sys", 1, "sys.mount");
        test_unit_name_mangle_with_suffix_one("/../sys", 1, "sys.mount");
        test_unit_name_mangle_with_suffix_one("/../sys/.", 1, "sys.mount");
        /* We don't skip the last '..', and it makes this an invalid device or mount name */
        test_unit_name_mangle_with_suffix_one("/.././sys/..", 1, "-..-.-sys-...service");
        test_unit_name_mangle_with_suffix_one("/.././sys", 1, "sys.mount");
        test_unit_name_mangle_with_suffix_one("/./.././../sys/", 1, "sys.mount");

        test_unit_name_mangle_with_suffix_one("/proc", 1, "proc.mount");
        test_unit_name_mangle_with_suffix_one("/../proc", 1, "proc.mount");
        test_unit_name_mangle_with_suffix_one("/../proc/.", 1, "proc.mount");
        /* We don't skip the last '..', and it makes this an invalid device or mount name */
        test_unit_name_mangle_with_suffix_one("/.././proc/..", 1, "-..-.-proc-...service");
        test_unit_name_mangle_with_suffix_one("/.././proc", 1, "proc.mount");
        test_unit_name_mangle_with_suffix_one("/./.././../proc/", 1, "proc.mount");
}

TEST_RET(unit_printf, .sd_booted = true) {
        _cleanup_free_ char
                *architecture, *os_image_version, *boot_id = NULL, *os_build_id,
                *hostname, *short_hostname, *pretty_hostname,
                *machine_id = NULL, *os_image_id, *os_id, *os_version_id, *os_variant_id,
                *user, *group, *uid, *gid, *home, *shell,
                *tmp_dir, *var_tmp_dir;
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_close_ int fd = -EBADF;
        Unit *u;
        int r;

        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/test-unit_printf.XXXXXX";
        fd = mkostemp_safe(filename);
        assert_se(fd >= 0);

        /* Using the specifier functions is admittedly a bit circular, but we don't want to reimplement the
         * logic a second time. We're at least testing that the hookup works. */
        assert_se(specifier_architecture('a', NULL, NULL, NULL, &architecture) >= 0);
        assert_se(architecture);
        assert_se(specifier_os_image_version('A', NULL, NULL, NULL, &os_image_version) >= 0);
        if (sd_booted() > 0) {
                assert_se(specifier_boot_id('b', NULL, NULL, NULL, &boot_id) >= 0);
                assert_se(boot_id);
        }
        assert_se(specifier_os_build_id('B', NULL, NULL, NULL, &os_build_id) >= 0);
        assert_se(hostname = gethostname_malloc());
        assert_se(specifier_short_hostname('l', NULL, NULL, NULL, &short_hostname) == 0);
        assert_se(short_hostname);
        assert_se(specifier_pretty_hostname('q', NULL, NULL, NULL, &pretty_hostname) == 0);
        assert_se(pretty_hostname);
        if (sd_id128_get_machine(NULL) >= 0) {
                assert_se(specifier_machine_id('m', NULL, NULL, NULL, &machine_id) >= 0);
                assert_se(machine_id);
        }
        assert_se(specifier_os_image_id('M', NULL, NULL, NULL, &os_image_id) >= 0);
        assert_se(specifier_os_id('o', NULL, NULL, NULL, &os_id) >= 0);
        assert_se(specifier_os_version_id('w', NULL, NULL, NULL, &os_version_id) >= 0);
        assert_se(specifier_os_variant_id('W', NULL, NULL, NULL, &os_variant_id) >= 0);
        assert_se(user = uid_to_name(getuid()));
        assert_se(group = gid_to_name(getgid()));
        assert_se(asprintf(&uid, UID_FMT, getuid()));
        assert_se(asprintf(&gid, UID_FMT, getgid()));
        assert_se(get_home_dir(&home) >= 0);
        assert_se(get_shell(&shell) >= 0);
        assert_se(specifier_tmp_dir('T', NULL, NULL, NULL, &tmp_dir) >= 0);
        assert_se(tmp_dir);
        assert_se(specifier_var_tmp_dir('V', NULL, NULL, NULL, &var_tmp_dir) >= 0);
        assert_se(var_tmp_dir);

        r = manager_new(RUNTIME_SCOPE_USER, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r))
                return log_tests_skipped_errno(r, "manager_new");
        assert_se(r == 0);

        assert_se(free_and_strdup(&m->cgroup_root, "/cgroup-root") == 1);

#define expect(unit, pattern, _expected)                                \
        {                                                               \
                _cleanup_free_ char *t = NULL;                          \
                assert_se(unit_full_printf(unit, pattern, &t) >= 0);    \
                const char *expected = strempty(_expected);             \
                printf("%s: result: %s\n    expect: %s\n", pattern, t, expected); \
                assert_se(fnmatch(expected, t, FNM_NOESCAPE) == 0);     \
        }

        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "blah.service") == 0);
        assert_se(unit_add_name(u, "blah.service") == 0);

        /* We need *a* file that exists, but it doesn't even need to have the right suffix. */
        assert_se(free_and_strdup(&u->fragment_path, filename) == 1);

        /* This sets the slice to /app.slice. */
        assert_se(unit_set_default_slice(u) == 1);

        /* general tests */
        expect(u, "%%", "%");
        expect(u, "%%s", "%s");
        expect(u, "%,", "%,");
        expect(u, "%", "%");

        /* normal unit */
        expect(u, "%a", architecture);
        expect(u, "%A", os_image_version);
        if (boot_id)
                expect(u, "%b", boot_id);
        expect(u, "%B", os_build_id);
        expect(u, "%H", hostname);
        expect(u, "%l", short_hostname);
        expect(u, "%q", pretty_hostname);
        if (machine_id)
                expect(u, "%m", machine_id);
        expect(u, "%M", os_image_id);
        expect(u, "%o", os_id);
        expect(u, "%w", os_version_id);
        expect(u, "%W", os_variant_id);
        expect(u, "%g", group);
        expect(u, "%G", gid);
        expect(u, "%u", user);
        expect(u, "%U", uid);
        expect(u, "%T", tmp_dir);
        expect(u, "%V", var_tmp_dir);

        expect(u, "%i", "");
        expect(u, "%I", "");
        expect(u, "%j", "blah");
        expect(u, "%J", "blah");
        expect(u, "%n", "blah.service");
        expect(u, "%N", "blah");
        expect(u, "%p", "blah");
        expect(u, "%P", "blah");
        expect(u, "%f", "/blah");
        expect(u, "%y", filename);
        expect(u, "%Y", "/tmp");
        expect(u, "%C", m->prefix[EXEC_DIRECTORY_CACHE]);
        expect(u, "%d", "*/credentials/blah.service");
        expect(u, "%E", m->prefix[EXEC_DIRECTORY_CONFIGURATION]);
        expect(u, "%L", m->prefix[EXEC_DIRECTORY_LOGS]);
        expect(u, "%S", m->prefix[EXEC_DIRECTORY_STATE]);
        expect(u, "%t", m->prefix[EXEC_DIRECTORY_RUNTIME]);
        expect(u, "%h", home);
        expect(u, "%s", shell);

        /* deprecated */
        expect(u, "%c", "/cgroup-root/app.slice/blah.service");
        expect(u, "%r", "/cgroup-root/app.slice");
        expect(u, "%R", "/cgroup-root");

        /* templated */
        assert_se(u = unit_new(m, sizeof(Service)));
        assert_se(unit_add_name(u, "blah@foo-foo.service") == 0);
        assert_se(unit_add_name(u, "blah@foo-foo.service") == 0);

        assert_se(free_and_strdup(&u->fragment_path, filename) == 1);

        /* This sets the slice to /app.slice/app-blah.slice. */
        assert_se(unit_set_default_slice(u) == 1);

        expect(u, "%i", "foo-foo");
        expect(u, "%I", "foo/foo");
        expect(u, "%j", "blah");
        expect(u, "%J", "blah");
        expect(u, "%n", "blah@foo-foo.service");
        expect(u, "%N", "blah@foo-foo");
        expect(u, "%p", "blah");
        expect(u, "%P", "blah");
        expect(u, "%f", "/foo/foo");
        expect(u, "%y", filename);
        expect(u, "%Y", "/tmp");
        expect(u, "%C", m->prefix[EXEC_DIRECTORY_CACHE]);
        expect(u, "%d", "*/credentials/blah@foo-foo.service");
        expect(u, "%E", m->prefix[EXEC_DIRECTORY_CONFIGURATION]);
        expect(u, "%L", m->prefix[EXEC_DIRECTORY_LOGS]);
        expect(u, "%S", m->prefix[EXEC_DIRECTORY_STATE]);
        expect(u, "%t", m->prefix[EXEC_DIRECTORY_RUNTIME]);
        expect(u, "%h", home);
        expect(u, "%s", shell);

        /* deprecated */
        expect(u, "%c", "/cgroup-root/app.slice/app-blah.slice/blah@foo-foo.service");
        expect(u, "%r", "/cgroup-root/app.slice/app-blah.slice");
        expect(u, "%R", "/cgroup-root");

        /* templated with components */
        assert_se(u = unit_new(m, sizeof(Slice)));
        assert_se(unit_add_name(u, "blah-blah\\x2d.slice") == 0);

        expect(u, "%i", "");
        expect(u, "%I", "");
        expect(u, "%j", "blah\\x2d");
        expect(u, "%J", "blah-");
        expect(u, "%n", "blah-blah\\x2d.slice");
        expect(u, "%N", "blah-blah\\x2d");
        expect(u, "%p", "blah-blah\\x2d");
        expect(u, "%P", "blah/blah-");
        expect(u, "%f", "/blah/blah-");

        /* deprecated */
        expect(u, "%c", "/cgroup-root/blah-blah\\x2d.slice");
        expect(u, "%r", "/cgroup-root");
        expect(u, "%R", "/cgroup-root");

#undef expect

        return 0;
}

TEST(unit_instance_is_valid) {
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

TEST(unit_prefix_is_valid) {
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

TEST(unit_name_change_suffix) {
        char *t;

        assert_se(unit_name_change_suffix("foo.mount", ".service", &t) == 0);
        ASSERT_STREQ(t, "foo.service");
        free(t);

        assert_se(unit_name_change_suffix("foo@stuff.service", ".socket", &t) == 0);
        ASSERT_STREQ(t, "foo@stuff.socket");
        free(t);
}

TEST(unit_name_build) {
        char *t;

        assert_se(unit_name_build("foo", "bar", ".service", &t) == 0);
        ASSERT_STREQ(t, "foo@bar.service");
        free(t);

        assert_se(unit_name_build("fo0-stUff_b", "bar", ".mount", &t) == 0);
        ASSERT_STREQ(t, "fo0-stUff_b@bar.mount");
        free(t);

        assert_se(unit_name_build("foo", NULL, ".service", &t) == 0);
        ASSERT_STREQ(t, "foo.service");
        free(t);
}

TEST(slice_name_is_valid) {
        assert_se( slice_name_is_valid(SPECIAL_ROOT_SLICE));
        assert_se( slice_name_is_valid("foo.slice"));
        assert_se( slice_name_is_valid("foo-bar.slice"));
        assert_se( slice_name_is_valid("foo-bar-baz.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz.slice"));
        assert_se(!slice_name_is_valid("foo-bar-baz-.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz-.slice"));
        assert_se(!slice_name_is_valid("foo-bar--baz.slice"));
        assert_se(!slice_name_is_valid("foo--bar--baz.slice"));
        assert_se(!slice_name_is_valid(".slice"));
        assert_se(!slice_name_is_valid(""));
        assert_se(!slice_name_is_valid("foo.service"));

        assert_se(!slice_name_is_valid("foo@.slice"));
        assert_se(!slice_name_is_valid("foo@bar.slice"));
        assert_se(!slice_name_is_valid("foo-bar@baz.slice"));
        assert_se(!slice_name_is_valid("foo@bar@baz.slice"));
        assert_se(!slice_name_is_valid("foo@bar-baz.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz@.slice"));
        assert_se(!slice_name_is_valid("foo-bar-baz@-.slice"));
        assert_se(!slice_name_is_valid("foo-bar-baz@a--b.slice"));
        assert_se(!slice_name_is_valid("-foo-bar-baz@-.slice"));
        assert_se(!slice_name_is_valid("foo-bar--baz@.slice"));
        assert_se(!slice_name_is_valid("foo--bar--baz@.slice"));
        assert_se(!slice_name_is_valid("@.slice"));
        assert_se(!slice_name_is_valid("foo@bar.service"));
}

TEST(build_subslice) {
        char *a;
        char *b;

        assert_se(slice_build_subslice(SPECIAL_ROOT_SLICE, "foo", &a) >= 0);
        assert_se(slice_build_subslice(a, "bar", &b) >= 0);
        free(a);
        assert_se(slice_build_subslice(b, "barfoo", &a) >= 0);
        free(b);
        assert_se(slice_build_subslice(a, "foobar", &b) >= 0);
        free(a);
        ASSERT_STREQ(b, "foo-bar-barfoo-foobar.slice");
        free(b);

        assert_se(slice_build_subslice("foo.service", "bar", &a) < 0);
        assert_se(slice_build_subslice("foo", "bar", &a) < 0);
}

static void test_build_parent_slice_one(const char *name, const char *expect, int ret) {
        _cleanup_free_ char *s = NULL;

        assert_se(slice_build_parent_slice(name, &s) == ret);
        ASSERT_STREQ(s, expect);
}

TEST(build_parent_slice) {
        test_build_parent_slice_one(SPECIAL_ROOT_SLICE, NULL, 0);
        test_build_parent_slice_one("foo.slice", SPECIAL_ROOT_SLICE, 1);
        test_build_parent_slice_one("foo-bar.slice", "foo.slice", 1);
        test_build_parent_slice_one("foo-bar-baz.slice", "foo-bar.slice", 1);
        test_build_parent_slice_one("foo-bar--baz.slice", NULL, -EINVAL);
        test_build_parent_slice_one("-foo-bar.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar-.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar.service", NULL, -EINVAL);
        test_build_parent_slice_one(".slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo@bar.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar@baz.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar--@baz.slice", NULL, -EINVAL);
        test_build_parent_slice_one("-foo-bar@bar.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo-bar@-.slice", NULL, -EINVAL);
        test_build_parent_slice_one("foo@bar.service", NULL, -EINVAL);
        test_build_parent_slice_one("@.slice", NULL, -EINVAL);
}

TEST(unit_name_to_instance) {
        UnitNameFlags r;
        char *instance;

        r = unit_name_to_instance("foo@bar.service", &instance);
        assert_se(r == UNIT_NAME_INSTANCE);
        ASSERT_STREQ(instance, "bar");
        free(instance);

        r = unit_name_to_instance("foo@.service", &instance);
        assert_se(r == UNIT_NAME_TEMPLATE);
        ASSERT_STREQ(instance, "");
        free(instance);

        r = unit_name_to_instance("fo0-stUff_b@b.service", &instance);
        assert_se(r == UNIT_NAME_INSTANCE);
        ASSERT_STREQ(instance, "b");
        free(instance);

        r = unit_name_to_instance("foo.service", &instance);
        assert_se(r == UNIT_NAME_PLAIN);
        assert_se(!instance);

        r = unit_name_to_instance("fooj@unk", &instance);
        assert_se(r < 0);
        assert_se(!instance);

        r = unit_name_to_instance("foo@", &instance);
        assert_se(r < 0);
        assert_se(!instance);
}

TEST(unit_name_escape) {
        _cleanup_free_ char *r = NULL;

        r = unit_name_escape("ab+-c.a/bc@foo.service");
        assert_se(r);
        ASSERT_STREQ(r, "ab\\x2b\\x2dc.a-bc\\x40foo.service");
}

static void test_u_n_t_one(const char *name, const char *expected, int ret) {
        _cleanup_free_ char *f = NULL;

        assert_se(unit_name_template(name, &f) == ret);
        printf("got: %s, expected: %s\n", strna(f), strna(expected));
        ASSERT_STREQ(f, expected);
}

TEST(unit_name_template) {
        test_u_n_t_one("foo@bar.service", "foo@.service", 0);
        test_u_n_t_one("foo.mount", NULL, -EINVAL);
}

static void test_unit_name_path_unescape_one(const char *name, const char *path, int ret) {
        _cleanup_free_ char *p = NULL;

        assert_se(unit_name_path_unescape(name, &p) == ret);
        ASSERT_STREQ(path, p);
}

TEST(unit_name_path_unescape) {
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

static void test_unit_name_to_prefix_one(const char *input, int ret, const char *output) {
        _cleanup_free_ char *k = NULL;

        assert_se(unit_name_to_prefix(input, &k) == ret);
        ASSERT_STREQ(k, output);
}

TEST(unit_name_to_prefix) {
        test_unit_name_to_prefix_one("foobar.service", 0, "foobar");
        test_unit_name_to_prefix_one("", -EINVAL, NULL);
        test_unit_name_to_prefix_one("foobar", -EINVAL, NULL);
        test_unit_name_to_prefix_one(".service", -EINVAL, NULL);
        test_unit_name_to_prefix_one("quux.quux", -EINVAL, NULL);
        test_unit_name_to_prefix_one("quux.mount", 0, "quux");
        test_unit_name_to_prefix_one("quux-quux.mount", 0, "quux-quux");
        test_unit_name_to_prefix_one("quux@bar.mount", 0, "quux");
        test_unit_name_to_prefix_one("quux-@.mount", 0, "quux-");
        test_unit_name_to_prefix_one("@.mount", -EINVAL, NULL);
}

static void test_unit_name_from_dbus_path_one(const char *input, int ret, const char *output) {
        _cleanup_free_ char *k = NULL;

        assert_se(unit_name_from_dbus_path(input, &k) == ret);
        ASSERT_STREQ(k, output);
}

TEST(unit_name_from_dbus_path) {
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dbus_2esocket", 0, "dbus.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/_2d_2emount", 0, "-.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/_2d_2eslice", 0, "-.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/accounts_2ddaemon_2eservice", 0, "accounts-daemon.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/auditd_2eservice", 0, "auditd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/basic_2etarget", 0, "basic.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/bluetooth_2etarget", 0, "bluetooth.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/boot_2eautomount", 0, "boot.automount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/boot_2emount", 0, "boot.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/btrfs_2emount", 0, "btrfs.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/cryptsetup_2dpre_2etarget", 0, "cryptsetup-pre.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/cryptsetup_2etarget", 0, "cryptsetup.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dbus_2eservice", 0, "dbus.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dbus_2esocket", 0, "dbus.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dcdrom_2edevice", 0, "dev-cdrom.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M120G2GC_5fCVPO044405HH120QGN_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M120G2GC_CVPO044405HH120QGN.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M120G2GC_5fCVPO044405HH120QGN_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M120G2GC_CVPO044405HH120QGN\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M160G2GC_5fCVPO951003RY160AGN_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M160G2GC_CVPO951003RY160AGN.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M160G2GC_5fCVPO951003RY160AGN_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M160G2GC_CVPO951003RY160AGN\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M160G2GC_5fCVPO951003RY160AGN_5cx2dpart2_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M160G2GC_CVPO951003RY160AGN\\x2dpart2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dINTEL_5fSSDSA2M160G2GC_5fCVPO951003RY160AGN_5cx2dpart3_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dINTEL_SSDSA2M160G2GC_CVPO951003RY160AGN\\x2dpart3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2data_5cx2dTSSTcorp_5fCDDVDW_5fTS_5cx2dL633C_5fR6176GLZB14646_2edevice", 0, "dev-disk-by\\x2did-ata\\x2dTSSTcorp_CDDVDW_TS\\x2dL633C_R6176GLZB14646.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x50015179591245ae_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x50015179591245ae.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x50015179591245ae_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x50015179591245ae\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x50015179591245ae_5cx2dpart2_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x50015179591245ae\\x2dpart2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x50015179591245ae_5cx2dpart3_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x50015179591245ae\\x2dpart3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x500151795946eab5_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x500151795946eab5.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2did_2dwwn_5cx2d0x500151795946eab5_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2did-wwn\\x2d0x500151795946eab5\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dlabel_2d_5cxe3_5cx82_5cxb7_5cxe3_5cx82_5cxb9_5cxe3_5cx83_5cx86_5cxe3_5cx83_5cxa0_5cxe3_5cx81_5cxa7_5cxe4_5cxba_5cx88_5cxe7_5cxb4_5cx84_5cxe6_5cxb8_5cx88_5cxe3_5cx81_5cxbf_2edevice", 0, "dev-disk-by\\x2dlabel-\\xe3\\x82\\xb7\\xe3\\x82\\xb9\\xe3\\x83\\x86\\xe3\\x83\\xa0\\xe3\\x81\\xa7\\xe4\\xba\\x88\\xe7\\xb4\\x84\\xe6\\xb8\\x88\\xe3\\x81\\xbf.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpartuuid_2d59834e50_5cx2d01_2edevice", 0, "dev-disk-by\\x2dpartuuid-59834e50\\x2d01.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpartuuid_2d63e2a7b3_5cx2d01_2edevice", 0, "dev-disk-by\\x2dpartuuid-63e2a7b3\\x2d01.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpartuuid_2d63e2a7b3_5cx2d02_2edevice", 0, "dev-disk-by\\x2dpartuuid-63e2a7b3\\x2d02.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpartuuid_2d63e2a7b3_5cx2d03_2edevice", 0, "dev-disk-by\\x2dpartuuid-63e2a7b3\\x2d03.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d1_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d1_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d1\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d1_5cx2dpart2_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d1\\x2dpart2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d1_5cx2dpart3_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d1\\x2dpart3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d2_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d6_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d6.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2dpath_2dpci_5cx2d0000_3a00_3a1f_2e2_5cx2data_5cx2d6_5cx2dpart1_2edevice", 0, "dev-disk-by\\x2dpath-pci\\x2d0000:00:1f.2\\x2data\\x2d6\\x2dpart1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2duuid_2d1A34E3F034E3CD37_2edevice", 0, "dev-disk-by\\x2duuid-1A34E3F034E3CD37.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2duuid_2dB670EBFE70EBC2EB_2edevice", 0, "dev-disk-by\\x2duuid-B670EBFE70EBC2EB.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2duuid_2dFCD4F509D4F4C6C4_2edevice", 0, "dev-disk-by\\x2duuid-FCD4F509D4F4C6C4.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2ddisk_2dby_5cx2duuid_2db49ead57_5cx2d907c_5cx2d446c_5cx2db405_5cx2d5ca6cd865f5e_2edevice", 0, "dev-disk-by\\x2duuid-b49ead57\\x2d907c\\x2d446c\\x2db405\\x2d5ca6cd865f5e.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dhugepages_2emount", 0, "dev-hugepages.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dmqueue_2emount", 0, "dev-mqueue.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2drfkill_2edevice", 0, "dev-rfkill.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsda1_2edevice", 0, "dev-sda1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsda2_2edevice", 0, "dev-sda2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsda3_2edevice", 0, "dev-sda3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsda_2edevice", 0, "dev-sda.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsdb1_2edevice", 0, "dev-sdb1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsdb_2edevice", 0, "dev-sdb.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dsr0_2edevice", 0, "dev-sr0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS0_2edevice", 0, "dev-ttyS0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS10_2edevice", 0, "dev-ttyS10.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS11_2edevice", 0, "dev-ttyS11.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS12_2edevice", 0, "dev-ttyS12.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS13_2edevice", 0, "dev-ttyS13.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS14_2edevice", 0, "dev-ttyS14.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS15_2edevice", 0, "dev-ttyS15.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS16_2edevice", 0, "dev-ttyS16.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS17_2edevice", 0, "dev-ttyS17.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS18_2edevice", 0, "dev-ttyS18.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS19_2edevice", 0, "dev-ttyS19.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS1_2edevice", 0, "dev-ttyS1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS20_2edevice", 0, "dev-ttyS20.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS21_2edevice", 0, "dev-ttyS21.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS22_2edevice", 0, "dev-ttyS22.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS23_2edevice", 0, "dev-ttyS23.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS24_2edevice", 0, "dev-ttyS24.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS25_2edevice", 0, "dev-ttyS25.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS26_2edevice", 0, "dev-ttyS26.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS27_2edevice", 0, "dev-ttyS27.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS28_2edevice", 0, "dev-ttyS28.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS29_2edevice", 0, "dev-ttyS29.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS2_2edevice", 0, "dev-ttyS2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS30_2edevice", 0, "dev-ttyS30.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS31_2edevice", 0, "dev-ttyS31.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS3_2edevice", 0, "dev-ttyS3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS4_2edevice", 0, "dev-ttyS4.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS5_2edevice", 0, "dev-ttyS5.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS6_2edevice", 0, "dev-ttyS6.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS7_2edevice", 0, "dev-ttyS7.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS8_2edevice", 0, "dev-ttyS8.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dev_2dttyS9_2edevice", 0, "dev-ttyS9.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dcmdline_2eservice", 0, "dracut-cmdline.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dinitqueue_2eservice", 0, "dracut-initqueue.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dmount_2eservice", 0, "dracut-mount.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dpre_2dmount_2eservice", 0, "dracut-pre-mount.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dpre_2dpivot_2eservice", 0, "dracut-pre-pivot.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dpre_2dtrigger_2eservice", 0, "dracut-pre-trigger.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dpre_2dudev_2eservice", 0, "dracut-pre-udev.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/dracut_2dshutdown_2eservice", 0, "dracut-shutdown.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/ebtables_2eservice", 0, "ebtables.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/emergency_2eservice", 0, "emergency.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/emergency_2etarget", 0, "emergency.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/fedora_2dimport_2dstate_2eservice", 0, "fedora-import-state.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/fedora_2dreadonly_2eservice", 0, "fedora-readonly.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/firewalld_2eservice", 0, "firewalld.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/getty_2dpre_2etarget", 0, "getty-pre.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/getty_2etarget", 0, "getty.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/getty_40tty1_2eservice", 0, "getty@tty1.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/graphical_2etarget", 0, "graphical.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/home_2emount", 0, "home.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/init_2escope", 0, "init.scope");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dcleanup_2eservice", 0, "initrd-cleanup.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dfs_2etarget", 0, "initrd-fs.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dparse_2detc_2eservice", 0, "initrd-parse-etc.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2droot_2ddevice_2etarget", 0, "initrd-root-device.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2droot_2dfs_2etarget", 0, "initrd-root-fs.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dswitch_2droot_2eservice", 0, "initrd-switch-root.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dswitch_2droot_2etarget", 0, "initrd-switch-root.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2dudevadm_2dcleanup_2ddb_2eservice", 0, "initrd-udevadm-cleanup-db.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/initrd_2etarget", 0, "initrd.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/ip6tables_2eservice", 0, "ip6tables.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/ipset_2eservice", 0, "ipset.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/iptables_2eservice", 0, "iptables.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/irqbalance_2eservice", 0, "irqbalance.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/kmod_2dstatic_2dnodes_2eservice", 0, "kmod-static-nodes.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/ldconfig_2eservice", 0, "ldconfig.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/lightdm_2eservice", 0, "lightdm.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/livesys_2dlate_2eservice", 0, "livesys-late.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/lm_5fsensors_2eservice", 0, "lm_sensors.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/local_2dfs_2dpre_2etarget", 0, "local-fs-pre.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/local_2dfs_2etarget", 0, "local-fs.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/machines_2etarget", 0, "machines.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/mcelog_2eservice", 0, "mcelog.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/multi_2duser_2etarget", 0, "multi-user.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/network_2dpre_2etarget", 0, "network-pre.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/network_2etarget", 0, "network.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/nss_2dlookup_2etarget", 0, "nss-lookup.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/nss_2duser_2dlookup_2etarget", 0, "nss-user-lookup.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/paths_2etarget", 0, "paths.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/plymouth_2dquit_2dwait_2eservice", 0, "plymouth-quit-wait.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/plymouth_2dquit_2eservice", 0, "plymouth-quit.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/plymouth_2dstart_2eservice", 0, "plymouth-start.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/polkit_2eservice", 0, "polkit.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/proc_2dsys_2dfs_2dbinfmt_5fmisc_2eautomount", 0, "proc-sys-fs-binfmt_misc.automount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/proc_2dsys_2dfs_2dbinfmt_5fmisc_2emount", 0, "proc-sys-fs-binfmt_misc.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/rc_2dlocal_2eservice", 0, "rc-local.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/remote_2dcryptsetup_2etarget", 0, "remote-cryptsetup.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/remote_2dfs_2dpre_2etarget", 0, "remote-fs-pre.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/remote_2dfs_2etarget", 0, "remote-fs.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/rescue_2eservice", 0, "rescue.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/rescue_2etarget", 0, "rescue.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/run_2duser_2d1000_2emount", 0, "run-user-1000.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/session_2d2_2escope", 0, "session-2.scope");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/shutdown_2etarget", 0, "shutdown.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/slices_2etarget", 0, "slices.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/smartd_2eservice", 0, "smartd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sockets_2etarget", 0, "sockets.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sound_2etarget", 0, "sound.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sshd_2dkeygen_2etarget", 0, "sshd-keygen.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sshd_2dkeygen_40ecdsa_2eservice", 0, "sshd-keygen@ecdsa.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sshd_2dkeygen_40ed25519_2eservice", 0, "sshd-keygen@ed25519.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sshd_2dkeygen_40rsa_2eservice", 0, "sshd-keygen@rsa.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sshd_2eservice", 0, "sshd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/swap_2etarget", 0, "swap.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a02_2e0_2dbacklight_2dacpi_5fvideo0_2edevice", 0, "sys-devices-pci0000:00-0000:00:02.0-backlight-acpi_video0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a02_2e0_2ddrm_2dcard0_2dcard0_5cx2dLVDS_5cx2d1_2dintel_5fbacklight_2edevice", 0, "sys-devices-pci0000:00-0000:00:02.0-drm-card0-card0\\x2dLVDS\\x2d1-intel_backlight.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1a_2e0_2dusb1_2d1_5cx2d1_2d1_5cx2d1_2e6_2d1_5cx2d1_2e6_3a1_2e0_2dbluetooth_2dhci0_2edevice", 0, "sys-devices-pci0000:00-0000:00:1a.0-usb1-1\\x2d1-1\\x2d1.6-1\\x2d1.6:1.0-bluetooth-hci0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1b_2e0_2dsound_2dcard0_2edevice", 0, "sys-devices-pci0000:00-0000:00:1b.0-sound-card0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1c_2e0_2d0000_3a02_3a00_2e0_2dnet_2dwlp2s0_2edevice", 0, "sys-devices-pci0000:00-0000:00:1c.0-0000:02:00.0-net-wlp2s0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1c_2e2_2d0000_3a04_3a00_2e0_2dnet_2denp4s0_2edevice", 0, "sys-devices-pci0000:00-0000:00:1c.2-0000:04:00.0-net-enp4s0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data1_2dhost0_2dtarget0_3a0_3a0_2d0_3a0_3a0_3a0_2dblock_2dsda_2dsda1_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata1-host0-target0:0:0-0:0:0:0-block-sda-sda1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data1_2dhost0_2dtarget0_3a0_3a0_2d0_3a0_3a0_3a0_2dblock_2dsda_2dsda2_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata1-host0-target0:0:0-0:0:0:0-block-sda-sda2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data1_2dhost0_2dtarget0_3a0_3a0_2d0_3a0_3a0_3a0_2dblock_2dsda_2dsda3_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata1-host0-target0:0:0-0:0:0:0-block-sda-sda3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data1_2dhost0_2dtarget0_3a0_3a0_2d0_3a0_3a0_3a0_2dblock_2dsda_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata1-host0-target0:0:0-0:0:0:0-block-sda.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data2_2dhost1_2dtarget1_3a0_3a0_2d1_3a0_3a0_3a0_2dblock_2dsr0_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata2-host1-target1:0:0-1:0:0:0-block-sr0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data6_2dhost5_2dtarget5_3a0_3a0_2d5_3a0_3a0_3a0_2dblock_2dsdb_2dsdb1_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata6-host5-target5:0:0-5:0:0:0-block-sdb-sdb1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dpci0000_3a00_2d0000_3a00_3a1f_2e2_2data6_2dhost5_2dtarget5_3a0_3a0_2d5_3a0_3a0_3a0_2dblock_2dsdb_2edevice", 0, "sys-devices-pci0000:00-0000:00:1f.2-ata6-host5-target5:0:0-5:0:0:0-block-sdb.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS0_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS10_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS10.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS11_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS11.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS12_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS12.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS13_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS13.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS14_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS14.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS15_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS15.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS16_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS16.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS17_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS17.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS18_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS18.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS19_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS19.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS1_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS1.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS20_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS20.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS21_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS21.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS22_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS22.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS23_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS23.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS24_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS24.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS25_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS25.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS26_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS26.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS27_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS27.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS28_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS28.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS29_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS29.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS2_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS2.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS30_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS30.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS31_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS31.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS3_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS3.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS4_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS4.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS5_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS5.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS6_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS6.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS7_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS7.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS8_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS8.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dplatform_2dserial8250_2dtty_2dttyS9_2edevice", 0, "sys-devices-platform-serial8250-tty-ttyS9.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2ddevices_2dvirtual_2dmisc_2drfkill_2edevice", 0, "sys-devices-virtual-misc-rfkill.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dfs_2dfuse_2dconnections_2emount", 0, "sys-fs-fuse-connections.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dkernel_2dconfig_2emount", 0, "sys-kernel-config.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dkernel_2ddebug_2emount", 0, "sys-kernel-debug.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dmodule_2dconfigfs_2edevice", 0, "sys-module-configfs.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dsubsystem_2dbluetooth_2ddevices_2dhci0_2edevice", 0, "sys-subsystem-bluetooth-devices-hci0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dsubsystem_2dnet_2ddevices_2denp4s0_2edevice", 0, "sys-subsystem-net-devices-enp4s0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sys_2dsubsystem_2dnet_2ddevices_2dwlp2s0_2edevice", 0, "sys-subsystem-net-devices-wlp2s0.device");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sysinit_2etarget", 0, "sysinit.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/syslog_2eservice", 0, "syslog.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/syslog_2esocket", 0, "syslog.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/syslog_2etarget", 0, "syslog.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/sysroot_2emount", 0, "sysroot.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2dgetty_2eslice", 0, "system-getty.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2dsshd_5cx2dkeygen_2eslice", 0, "system-sshd\\x2dkeygen.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2dsystemd_5cx2dbacklight_2eslice", 0, "system-systemd\\x2dbacklight.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2dsystemd_5cx2dcoredump_2eslice", 0, "system-systemd\\x2dcoredump.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2duser_5cx2druntime_5cx2ddir_2eslice", 0, "system-user\\x2druntime\\x2ddir.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/system_2eslice", 0, "system.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dask_2dpassword_2dconsole_2epath", 0, "systemd-ask-password-console.path");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dask_2dpassword_2dconsole_2eservice", 0, "systemd-ask-password-console.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dask_2dpassword_2dwall_2epath", 0, "systemd-ask-password-wall.path");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dask_2dpassword_2dwall_2eservice", 0, "systemd-ask-password-wall.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dbacklight_40backlight_3aacpi_5fvideo0_2eservice", 0, "systemd-backlight@backlight:acpi_video0.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dbacklight_40backlight_3aintel_5fbacklight_2eservice", 0, "systemd-backlight@backlight:intel_backlight.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dbinfmt_2eservice", 0, "systemd-binfmt.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dcoredump_2esocket", 0, "systemd-coredump.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dcoredump_400_2eservice", 0, "systemd-coredump@0.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dfirstboot_2eservice", 0, "systemd-firstboot.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dfsck_2droot_2eservice", 0, SPECIAL_FSCK_ROOT_SERVICE);
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dhwdb_2dupdate_2eservice", 0, "systemd-hwdb-update.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dinitctl_2eservice", 0, "systemd-initctl.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dinitctl_2esocket", 0, "systemd-initctl.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournal_2dcatalog_2dupdate_2eservice", 0, "systemd-journal-catalog-update.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournal_2dflush_2eservice", 0, "systemd-journal-flush.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournald_2daudit_2esocket", 0, "systemd-journald-audit.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournald_2ddev_2dlog_2esocket", 0, "systemd-journald-dev-log.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournald_2eservice", 0, "systemd-journald.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2djournald_2esocket", 0, "systemd-journald.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dlogind_2eservice", 0, "systemd-logind.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dmachine_2did_2dcommit_2eservice", 0, "systemd-machine-id-commit.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dmodules_2dload_2eservice", 0, "systemd-modules-load.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dnetworkd_2eservice", 0, "systemd-networkd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dnetworkd_2esocket", 0, "systemd-networkd.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2drandom_2dseed_2eservice", 0, "systemd-random-seed.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dremount_2dfs_2eservice", 0, "systemd-remount-fs.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dresolved_2eservice", 0, "systemd-resolved.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2drfkill_2eservice", 0, "systemd-rfkill.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2drfkill_2esocket", 0, "systemd-rfkill.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dsysctl_2eservice", 0, "systemd-sysctl.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dsysusers_2eservice", 0, "systemd-sysusers.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dtimesyncd_2eservice", 0, "systemd-timesyncd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dtmpfiles_2dclean_2eservice", 0, "systemd-tmpfiles-clean.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dtmpfiles_2dclean_2etimer", 0, "systemd-tmpfiles-clean.timer");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dtmpfiles_2dsetup_2ddev_2eservice", 0, "systemd-tmpfiles-setup-dev.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dtmpfiles_2dsetup_2eservice", 0, "systemd-tmpfiles-setup.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dudev_2dtrigger_2eservice", 0, "systemd-udev-trigger.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dudevd_2dcontrol_2esocket", 0, "systemd-udevd-control.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dudevd_2dkernel_2esocket", 0, "systemd-udevd-kernel.socket");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dudevd_2eservice", 0, "systemd-udevd.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dupdate_2ddone_2eservice", 0, "systemd-update-done.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dupdate_2dutmp_2drunlevel_2eservice", 0, "systemd-update-utmp-runlevel.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dupdate_2dutmp_2eservice", 0, "systemd-update-utmp.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2duser_2dsessions_2eservice", 0, "systemd-user-sessions.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/systemd_2dvconsole_2dsetup_2eservice", 0, "systemd-vconsole-setup.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/time_2dsync_2etarget", 0, "time-sync.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/timers_2etarget", 0, "timers.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/tmp_2emount", 0, "tmp.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/umount_2etarget", 0, "umount.target");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/unbound_2danchor_2eservice", 0, "unbound-anchor.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/unbound_2danchor_2etimer", 0, "unbound-anchor.timer");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/upower_2eservice", 0, "upower.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/user_2d1000_2eslice", 0, "user-1000.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/user_2druntime_2ddir_401000_2eservice", 0, "user-runtime-dir@1000.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/user_2eslice", 0, "user.slice");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/user_401000_2eservice", 0, "user@1000.service");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/usr_2dlocal_2dtexlive_2emount", 0, "usr-local-texlive.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/var_2dlib_2dmachines_2emount", 0, "var-lib-machines.mount");
        test_unit_name_from_dbus_path_one("/org/freedesktop/systemd1/unit/wpa_5fsupplicant_2eservice", 0, "wpa_supplicant.service");
}

TEST(unit_name_prefix_equal) {
        assert_se(unit_name_prefix_equal("a.service", "a.service"));
        assert_se(unit_name_prefix_equal("a.service", "a.mount"));
        assert_se(unit_name_prefix_equal("a@b.service", "a.service"));
        assert_se(unit_name_prefix_equal("a@b.service", "a@c.service"));

        assert_se(!unit_name_prefix_equal("a.service", "b.service"));
        assert_se(!unit_name_prefix_equal("a.service", "b.mount"));
        assert_se(!unit_name_prefix_equal("a@a.service", "b.service"));
        assert_se(!unit_name_prefix_equal("a@a.service", "b@a.service"));
        assert_se(!unit_name_prefix_equal("a", "b"));
        assert_se(!unit_name_prefix_equal("a", "a"));
}

static int intro(void) {
        if (enter_cgroup_subroot(NULL) == -ENOMEDIUM)
                return log_tests_skipped("cgroupfs not available");

        assert_se(runtime_dir = setup_fake_runtime_dir());
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
