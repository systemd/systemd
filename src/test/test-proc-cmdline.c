/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "env-util.h"
#include "errno-util.h"
#include "initrd-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static int obj;

static int parse_item(const char *key, const char *value, void *data) {
        assert_se(key);
        assert_se(data == &obj);

        log_info("kernel cmdline option <%s> = <%s>", key, strna(value));
        return 0;
}

TEST(proc_cmdline_parse) {
        assert_se(proc_cmdline_parse(parse_item, &obj, PROC_CMDLINE_STRIP_RD_PREFIX) >= 0);
}

TEST(proc_cmdline_override) {
        _cleanup_free_ char *line = NULL, *value = NULL;
        _cleanup_strv_free_ char **args = NULL;

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm some_arg_with_space='foo bar' and_one_more=\"zzz aaa\"") == 0);
        assert_se(putenv((char*) "SYSTEMD_EFI_OPTIONS=different") == 0);

        /* First test if the overrides for /proc/cmdline still work */
        assert_se(proc_cmdline(&line) >= 0);
        assert_se(streq(line, "foo_bar=quux wuff-piep=tuet zumm some_arg_with_space='foo bar' and_one_more=\"zzz aaa\""));
        line = mfree(line);
        assert_se(proc_cmdline_strv(&args) >= 0);
        assert_se(strv_equal(args, STRV_MAKE("foo_bar=quux", "wuff-piep=tuet", "zumm", "some_arg_with_space=foo bar", "and_one_more=zzz aaa")));
        args = strv_free(args);

        /* Test if parsing makes uses of the override */
        assert_se(proc_cmdline_get_key("foo_bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("some_arg_with_space", 0, &value) > 0 && streq_ptr(value, "foo bar"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("and_one_more", 0, &value) > 0 && streq_ptr(value, "zzz aaa"));
        value = mfree(value);

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=hoge") == 0);
        assert_se(putenv((char*) "SYSTEMD_EFI_OPTIONS=foo_bar=quux wuff-piep=tuet zumm some_arg_with_space='foo bar' and_one_more=\"zzz aaa\"") == 0);

        assert_se(proc_cmdline(&line) >= 0);
        assert_se(streq(line, "hoge"));
        line = mfree(line);
        assert_se(proc_cmdline_strv(&args) >= 0);
        assert_se(strv_equal(args, STRV_MAKE("hoge")));
        args = strv_free(args);

        assert_se(proc_cmdline_get_key("foo_bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("some_arg_with_space", 0, &value) > 0 && streq_ptr(value, "foo bar"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("and_one_more", 0, &value) > 0 && streq_ptr(value, "zzz aaa"));
        value = mfree(value);
}

static int parse_item_given(const char *key, const char *value, void *data) {
        assert_se(key);
        assert_se(data);

        bool *strip = data;

        log_info("%s: option <%s> = <%s>", __func__, key, strna(value));
        if (proc_cmdline_key_streq(key, "foo_bar"))
                assert_se(streq(value, "quux"));
        else if (proc_cmdline_key_streq(key, "wuff-piep"))
                assert_se(streq(value, "tuet "));
        else if (proc_cmdline_key_streq(key, "space"))
                assert_se(streq(value, "x y z"));
        else if (proc_cmdline_key_streq(key, "miepf"))
                assert_se(streq(value, "uuu"));
        else if (in_initrd() && *strip && proc_cmdline_key_streq(key, "zumm"))
                assert_se(!value);
        else if (in_initrd() && !*strip && proc_cmdline_key_streq(key, "rd.zumm"))
                assert_se(!value);
        else
                assert_not_reached();

        return 0;
}

static void test_proc_cmdline_given_one(bool flip_initrd) {
        log_info("/* %s (flip: %s) */", __func__, yes_no(flip_initrd));

        if (flip_initrd)
                in_initrd_force(!in_initrd());

        bool t = true, f = false;
        assert_se(proc_cmdline_parse(parse_item_given, &t, PROC_CMDLINE_STRIP_RD_PREFIX) >= 0);
        assert_se(proc_cmdline_parse(parse_item_given, &f, 0) >= 0);

        if (flip_initrd)
                in_initrd_force(!in_initrd());
}

TEST(test_proc_cmdline_given) {
        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=\"tuet \" rd.zumm space='x y z' miepf=\"uuu\"") == 0);
        assert_se(putenv((char*) "SYSTEMD_EFI_OPTIONS=miepf=\"uuu\"") == 0);

        test_proc_cmdline_given_one(false);
        /* Repeat the same thing, but now flip our ininitrdness */
        test_proc_cmdline_given_one(true);
}

TEST(proc_cmdline_get_key) {
        _cleanup_free_ char *value = NULL;

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm-ghh spaaace='ö ü ß' ticks=\"''\"\n\nkkk=uuu\n\n\n") == 0);

        assert_se(proc_cmdline_get_key("", 0, &value) == -EINVAL);
        assert_se(proc_cmdline_get_key("abc", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("abc", 0, &value) == 0 && value == NULL);
        assert_se(proc_cmdline_get_key("abc", PROC_CMDLINE_VALUE_OPTIONAL, &value) == 0 && value == NULL);

        assert_se(proc_cmdline_get_key("foo_bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo_bar", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo_bar", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("foo-bar", 0, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "quux"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("foo-bar", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, NULL) == -EINVAL);

        assert_se(proc_cmdline_get_key("wuff-piep", 0, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff-piep", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", 0, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && streq_ptr(value, "tuet"));
        value = mfree(value);
        assert_se(proc_cmdline_get_key("wuff_piep", 0, NULL) == 0);
        assert_se(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, NULL) == -EINVAL);

        assert_se(proc_cmdline_get_key("zumm-ghh", 0, &value) == 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm-ghh", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm-ghh", 0, NULL) > 0);
        assert_se(proc_cmdline_get_key("zumm_ghh", 0, &value) == 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm_ghh", PROC_CMDLINE_VALUE_OPTIONAL, &value) > 0 && value == NULL);
        assert_se(proc_cmdline_get_key("zumm_ghh", 0, NULL) > 0);

        assert_se(proc_cmdline_get_key("spaaace", 0, &value) > 0 && streq_ptr(value, "ö ü ß"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("ticks", 0, &value) > 0 && streq_ptr(value, "''"));
        value = mfree(value);

        assert_se(proc_cmdline_get_key("kkk", 0, &value) > 0 && streq_ptr(value, "uuu"));
}

TEST(proc_cmdline_get_bool) {
        bool value = false;

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar bar-waldo=1 x_y-z=0 quux=miep\nda=yes\nthe=1") == 0);
        assert_se(putenv((char*) "SYSTEMD_EFI_OPTIONS=") == 0);

        assert_se(proc_cmdline_get_bool("", &value) == -EINVAL);
        assert_se(proc_cmdline_get_bool("abc", &value) == 0 && value == false);
        assert_se(proc_cmdline_get_bool("foo_bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("foo-bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar-waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar_waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("x_y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x_y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("quux", &value) == -EINVAL && value == false);
        assert_se(proc_cmdline_get_bool("da", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("the", &value) > 0 && value == true);
}

#if ENABLE_EFI
TEST(proc_cmdline_get_bool_efi) {
        bool value = false;

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=") == 0);
        assert_se(putenv((char*) "SYSTEMD_EFI_OPTIONS=foo_bar bar-waldo=1 x_y-z=0 quux=miep\nda=yes\nthe=1") == 0);

        assert_se(proc_cmdline_get_bool("", &value) == -EINVAL);
        assert_se(proc_cmdline_get_bool("abc", &value) == 0 && value == false);
        assert_se(proc_cmdline_get_bool("foo_bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("foo-bar", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar-waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("bar_waldo", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("x_y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y-z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x-y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("x_y_z", &value) > 0 && value == false);
        assert_se(proc_cmdline_get_bool("quux", &value) == -EINVAL && value == false);
        assert_se(proc_cmdline_get_bool("da", &value) > 0 && value == true);
        assert_se(proc_cmdline_get_bool("the", &value) > 0 && value == true);
}
#endif

TEST(proc_cmdline_get_key_many) {
        _cleanup_free_ char *value1 = NULL, *value2 = NULL, *value3 = NULL, *value4 = NULL, *value5 = NULL, *value6 = NULL, *value7 = NULL;

        assert_se(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm SPACE='one two' doubleticks=\" aaa aaa \"\n\nzummm='\n'\n") == 0);

        assert_se(proc_cmdline_get_key_many(0,
                                            "wuff-piep", &value3,
                                            "foo_bar", &value1,
                                            "idontexist", &value2,
                                            "zumm", &value4,
                                            "SPACE", &value5,
                                            "doubleticks", &value6,
                                            "zummm", &value7) == 5);

        assert_se(streq_ptr(value1, "quux"));
        assert_se(!value2);
        assert_se(streq_ptr(value3, "tuet"));
        assert_se(!value4);
        assert_se(streq_ptr(value5, "one two"));
        assert_se(streq_ptr(value6, " aaa aaa "));
        assert_se(streq_ptr(value7, "\n"));
}

TEST(proc_cmdline_key_streq) {
        assert_se(proc_cmdline_key_streq("", ""));
        assert_se(proc_cmdline_key_streq("a", "a"));
        assert_se(!proc_cmdline_key_streq("", "a"));
        assert_se(!proc_cmdline_key_streq("a", ""));
        assert_se(proc_cmdline_key_streq("a", "a"));
        assert_se(!proc_cmdline_key_streq("a", "b"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x-y-z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x_y_z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x-y_z"));
        assert_se(proc_cmdline_key_streq("x-y-z", "x_y-z"));
        assert_se(proc_cmdline_key_streq("x_y-z", "x-y_z"));
        assert_se(!proc_cmdline_key_streq("x_y-z", "x-z_z"));
}

TEST(proc_cmdline_key_startswith) {
        assert_se(proc_cmdline_key_startswith("", ""));
        assert_se(proc_cmdline_key_startswith("x", ""));
        assert_se(!proc_cmdline_key_startswith("", "x"));
        assert_se(proc_cmdline_key_startswith("x", "x"));
        assert_se(!proc_cmdline_key_startswith("x", "y"));
        assert_se(!proc_cmdline_key_startswith("foo-bar", "quux"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo-bar"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo_bar"));
        assert_se(proc_cmdline_key_startswith("foo-bar", "foo_"));
        assert_se(!proc_cmdline_key_startswith("foo-bar", "foo_xx"));
}

#define test_proc_cmdline_filter_pid1_args_one(nulstr, expected)        \
        ({                                                              \
                _cleanup_strv_free_ char **a = NULL, **b = NULL;        \
                const char s[] = (nulstr);                              \
                                                                        \
                /* This emulates get_process_cmdline_strv(). */         \
                assert_se(a = strv_parse_nulstr_full(s, ELEMENTSOF(s),  \
                                                     /* drop_trailing_nuls = */ true)); \
                assert_se(proc_cmdline_filter_pid1_args(a, &b) >= 0);   \
                assert_se(strv_equal(b, expected));                     \
        })

TEST(proc_cmdline_filter_pid1_args) {
        test_proc_cmdline_filter_pid1_args_one("systemd\0",
                                               STRV_MAKE_EMPTY);

        test_proc_cmdline_filter_pid1_args_one("systemd\0"
                                               "hoge\0"
                                               "-x\0"
                                               "foo\0"
                                               "--aaa\0"
                                               "var\0",
                                               STRV_MAKE("hoge", "foo", "var"));

        test_proc_cmdline_filter_pid1_args_one("/usr/lib/systemd/systemd\0"
                                               "--switched-root\0"
                                               "--system\0"
                                               "--deserialize\030\0"   /* followed with space */
                                               "--deserialize=31\0"    /* followed with '=' */
                                               "--exit-code=42\0"
                                               "\0\0\0"
                                               "systemd.log_level=debug\0"
                                               "--unit\0foo.target\0"
                                               "  '  quoted '\0"
                                               "systemd.log_target=console\0"
                                               "\t\0"
                                               "  arg   with   space \0"
                                               "3\0"
                                               "\0\0\0",
                                               STRV_MAKE("", "", "", "systemd.log_level=debug", "  '  quoted '", "systemd.log_target=console", "\t", "  arg   with   space ", "3"));
}

static int intro(void) {
        if (access("/proc/cmdline", R_OK) < 0 && ERRNO_IS_PRIVILEGE(errno))
                return log_tests_skipped("can't read /proc/cmdline");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_INFO, intro);
