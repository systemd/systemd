/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "xdg-autostart-service.h"

TEST(translate_name) {
        _cleanup_free_ char *t = NULL;

        assert_se(t = xdg_autostart_service_translate_name("a-b.blub.desktop"));
        assert_se(streq(t, "app-a\\x2db.blub@autostart.service"));
}

static void test_xdg_format_exec_start_one(const char *exec, const char *expected) {
        _cleanup_free_ char* out = NULL;

        xdg_autostart_format_exec_start(exec, &out);
        log_info("In: '%s', out: '%s', expected: '%s'", exec, out, expected);
        assert_se(streq(out, expected));
}

TEST(xdg_format_exec_start) {
        _cleanup_free_ char *home = NULL;
        _cleanup_free_ char *expected1 = NULL, *expected2 = NULL;

        assert_se(get_home_dir(&home) >= 0);

        test_xdg_format_exec_start_one("/bin/sleep 100", "/bin/sleep 100");

        /* All standardised % identifiers are stripped. */
        test_xdg_format_exec_start_one("/bin/sleep %f \"%F\" %u %U %d %D\t%n %N %i %c %k %v %m", "/bin/sleep");

        /* Unknown % identifier currently remain, but are escaped. */
        test_xdg_format_exec_start_one("/bin/sleep %X \"%Y\"", "/bin/sleep %%X %%Y");

        test_xdg_format_exec_start_one("/bin/sleep \";\\\"\"", "/bin/sleep \";\\\"\"");

        /* tilde is expanded only if standalone or at the start of a path */
        expected1 = strjoin("/bin/ls ", home);
        test_xdg_format_exec_start_one("/bin/ls ~", expected1);
        expected2 = strjoin("/bin/ls ", home, "/foo");
        test_xdg_format_exec_start_one("/bin/ls \"~/foo\"", expected2);
        test_xdg_format_exec_start_one("/bin/ls ~foo", "/bin/ls ~foo");
        test_xdg_format_exec_start_one("/bin/ls foo~", "/bin/ls foo~");
}

static const char* const xdg_desktop_file[] = {
        ("[Desktop Entry]\n"
         "Exec\t =\t /bin/sleep 100\n" /* Whitespace Before/After = must be ignored */
         "OnlyShowIn = A;B;\n"
         "NotShowIn=C;;D\\\\\\;;E\n"), /* "C", "", "D\;", "E" */

        ("[Desktop Entry]\n"
         "Exec=a\n"
         "Exec=b\n"),

        ("[Desktop Entry]\n"
         "Hidden=\t true\n"),
        ("[Desktop Entry]\n"
         "Hidden=\t True\n"),
};

static void test_xdg_desktop_parse_one(unsigned i, const char *s) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-xdg-autostart-parser.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(xdg_autostart_service_freep) XdgAutostartService *service = NULL;

        log_info("== %s[%u] ==", __func__, i);

        assert_se(fmkostemp_safe(name, "r+", &f) == 0);
        assert_se(fwrite(s, strlen(s), 1, f) == 1);
        rewind(f);

        assert_se(service = xdg_autostart_service_parse_desktop(name));

        switch (i) {
        case 0:
                assert_se(streq(service->exec_string, "/bin/sleep 100"));
                assert_se(strv_equal(service->only_show_in, STRV_MAKE("A", "B")));
                assert_se(strv_equal(service->not_show_in, STRV_MAKE("C", "D\\;", "E")));
                assert_se(!service->hidden);
                break;
        case 1:
                /* The second entry is not permissible and will be ignored (and error logged). */
                assert_se(streq(service->exec_string, "a"));
                break;
        case 2:
        case 3:
                assert_se(service->hidden);
                break;
        }
}

TEST(xdg_desktop_parse) {
        for (size_t i = 0; i < ELEMENTSOF(xdg_desktop_file); i++)
                test_xdg_desktop_parse_one(i, xdg_desktop_file[i]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
