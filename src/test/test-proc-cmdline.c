/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "initrd-util.h"
#include "log.h"
#include "nulstr-util.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static int obj;

static int parse_item(const char *key, const char *value, void *data) {
        ASSERT_NOT_NULL(key);
        ASSERT_PTR_EQ(data, &obj);

        log_info("kernel cmdline option <%s> = <%s>", key, strna(value));
        return 0;
}

TEST(proc_cmdline_parse) {
        ASSERT_OK(proc_cmdline_parse(parse_item, &obj, PROC_CMDLINE_STRIP_RD_PREFIX));
}

TEST(proc_cmdline_override) {
        _cleanup_free_ char *line = NULL, *value = NULL;
        _cleanup_strv_free_ char **args = NULL;

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm some_arg_with_space='foo bar' and_one_more=\"zzz aaa\""));

        /* First test if the overrides for /proc/cmdline still work */
        ASSERT_OK(proc_cmdline(&line));
        ASSERT_STREQ(line, "foo_bar=quux wuff-piep=tuet zumm some_arg_with_space='foo bar' and_one_more=\"zzz aaa\"");
        line = mfree(line);
        ASSERT_OK(proc_cmdline_strv(&args));
        ASSERT_STRV_EQ(args, STRV_MAKE("foo_bar=quux", "wuff-piep=tuet", "zumm", "some_arg_with_space=foo bar", "and_one_more=zzz aaa"));
        args = strv_free(args);

        /* Test if parsing makes uses of the override */
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("foo_bar", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "quux");
        value = mfree(value);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("some_arg_with_space", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "foo bar");
        value = mfree(value);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("and_one_more", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "zzz aaa");
        value = mfree(value);

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=hoge"));

        ASSERT_OK(proc_cmdline(&line));
        ASSERT_STREQ(line, "hoge");
        line = mfree(line);
        ASSERT_OK(proc_cmdline_strv(&args));
        ASSERT_STRV_EQ(args, STRV_MAKE("hoge"));
        args = strv_free(args);
}

static int parse_item_given(const char *key, const char *value, void *data) {
        ASSERT_NOT_NULL(key);
        ASSERT_NOT_NULL(data);

        bool *strip = data;

        log_info("%s: option <%s> = <%s>", __func__, key, strna(value));
        if (proc_cmdline_key_streq(key, "foo_bar"))
                ASSERT_STREQ(value, "quux");
        else if (proc_cmdline_key_streq(key, "wuff-piep"))
                ASSERT_STREQ(value, "tuet ");
        else if (proc_cmdline_key_streq(key, "space"))
                ASSERT_STREQ(value, "x y z");
        else if (proc_cmdline_key_streq(key, "miepf"))
                ASSERT_STREQ(value, "uuu");
        else if (in_initrd() && *strip && proc_cmdline_key_streq(key, "zumm"))
                ASSERT_NULL(value);
        else if (in_initrd() && !*strip && proc_cmdline_key_streq(key, "rd.zumm"))
                ASSERT_NULL(value);
        else
                assert_not_reached();

        return 0;
}

static void test_proc_cmdline_given_one(bool flip_initrd) {
        log_info("/* %s (flip: %s) */", __func__, yes_no(flip_initrd));

        if (flip_initrd)
                in_initrd_force(!in_initrd());

        bool t = true, f = false;
        ASSERT_OK(proc_cmdline_parse(parse_item_given, &t, PROC_CMDLINE_STRIP_RD_PREFIX));
        ASSERT_OK(proc_cmdline_parse(parse_item_given, &f, /* flags= */ 0));

        if (flip_initrd)
                in_initrd_force(!in_initrd());
}

TEST(proc_cmdline_given) {
        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=\"tuet \" rd.zumm space='x y z' miepf=\"uuu\""));

        test_proc_cmdline_given_one(/* flip_initrd= */ false);
        /* Repeat the same thing, but now flip our ininitrdness */
        test_proc_cmdline_given_one(/* flip_initrd= */ true);
}

TEST(proc_cmdline_get_key) {
        _cleanup_free_ char *value = NULL;

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm-ghh spaaace='ö ü ß' ticks=\"''\"\n\nkkk=uuu\n\n\n"));

        ASSERT_ERROR(proc_cmdline_get_key("", /* flags= */ 0, &value), EINVAL);
        ASSERT_OK_EQ(proc_cmdline_get_key("abc", /* flags= */ 0, /* ret_value= */ NULL), 0);
        ASSERT_OK_EQ(proc_cmdline_get_key("abc", /* flags= */ 0, &value), 0);
        ASSERT_NULL(value);
        ASSERT_OK_EQ(proc_cmdline_get_key("abc", PROC_CMDLINE_VALUE_OPTIONAL, &value), 0);
        ASSERT_NULL(value);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("foo_bar", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "quux");
        value = mfree(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("foo_bar", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_STREQ(value, "quux");
        value = mfree(value);
        ASSERT_OK_EQ(proc_cmdline_get_key("foo_bar", /* flags= */ 0, /* ret_value= */ NULL), 0);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("foo-bar", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "quux");
        value = mfree(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_STREQ(value, "quux");
        value = mfree(value);
        ASSERT_OK_EQ(proc_cmdline_get_key("foo-bar", /* flags= */ 0, /* ret_value= */ NULL), 0);
        ASSERT_ERROR(proc_cmdline_get_key("foo-bar", PROC_CMDLINE_VALUE_OPTIONAL, /* ret_value= */ NULL), EINVAL);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("wuff-piep", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "tuet");
        value = mfree(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("wuff-piep", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_STREQ(value, "tuet");
        value = mfree(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("wuff_piep", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "tuet");
        value = mfree(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_STREQ(value, "tuet");
        value = mfree(value);
        ASSERT_OK_EQ(proc_cmdline_get_key("wuff_piep", /* flags= */ 0, /* ret_value= */ NULL), 0);
        ASSERT_ERROR(proc_cmdline_get_key("wuff_piep", PROC_CMDLINE_VALUE_OPTIONAL, /* ret_value= */ NULL), EINVAL);

        ASSERT_OK_EQ(proc_cmdline_get_key("zumm-ghh", /* flags= */ 0, &value), 0);
        ASSERT_NULL(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("zumm-ghh", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_NULL(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("zumm-ghh", /* flags= */ 0, /* ret_value= */ NULL));
        ASSERT_OK_EQ(proc_cmdline_get_key("zumm_ghh", /* flags= */ 0, &value), 0);
        ASSERT_NULL(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("zumm_ghh", PROC_CMDLINE_VALUE_OPTIONAL, &value));
        ASSERT_NULL(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_key("zumm_ghh", /* flags= */ 0, /* ret_value= */ NULL));

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("spaaace", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "ö ü ß");
        value = mfree(value);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("ticks", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "''");
        value = mfree(value);

        ASSERT_OK_POSITIVE(proc_cmdline_get_key("kkk", /* flags= */ 0, &value));
        ASSERT_STREQ(value, "uuu");
}

TEST(proc_cmdline_get_bool) {
        bool value = false;

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar bar-waldo=1 x_y-z=0 quux=miep\nda=yes\nthe=1"));

        ASSERT_ERROR(proc_cmdline_get_bool("", /* flags= */ 0, &value), EINVAL);
        ASSERT_OK_EQ(proc_cmdline_get_bool("abc", /* flags= */ 0, &value), 0);
        ASSERT_FALSE(value);
        ASSERT_OK_EQ(proc_cmdline_get_bool("unspecified", PROC_CMDLINE_TRUE_WHEN_MISSING, &value), 0);
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("foo_bar", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("foo-bar", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("bar-waldo", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("bar_waldo", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("x_y-z", /* flags= */ 0, &value));
        ASSERT_FALSE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("x-y-z", /* flags= */ 0, &value));
        ASSERT_FALSE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("x-y_z", /* flags= */ 0, &value));
        ASSERT_FALSE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("x_y_z", /* flags= */ 0, &value));
        ASSERT_FALSE(value);
        ASSERT_ERROR(proc_cmdline_get_bool("quux", /* flags= */ 0, &value), EINVAL);
        ASSERT_FALSE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("da", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
        ASSERT_OK_POSITIVE(proc_cmdline_get_bool("the", /* flags= */ 0, &value));
        ASSERT_TRUE(value);
}

TEST(proc_cmdline_get_key_many) {
        _cleanup_free_ char *value1 = NULL, *value2 = NULL, *value3 = NULL, *value4 = NULL, *value5 = NULL, *value6 = NULL, *value7 = NULL;

        ASSERT_OK_ZERO_ERRNO(putenv((char*) "SYSTEMD_PROC_CMDLINE=foo_bar=quux wuff-piep=tuet zumm SPACE='one two' doubleticks=\" aaa aaa \"\n\nzummm='\n'\n"));

        ASSERT_OK_EQ(proc_cmdline_get_key_many(0,
                                               "wuff-piep", &value3,
                                               "foo_bar", &value1,
                                               "idontexist", &value2,
                                               "zumm", &value4,
                                               "SPACE", &value5,
                                               "doubleticks", &value6,
                                               "zummm", &value7), 5);

        ASSERT_STREQ(value1, "quux");
        ASSERT_NULL(value2);
        ASSERT_STREQ(value3, "tuet");
        ASSERT_NULL(value4);
        ASSERT_STREQ(value5, "one two");
        ASSERT_STREQ(value6, " aaa aaa ");
        ASSERT_STREQ(value7, "\n");
}

TEST(proc_cmdline_key_streq) {
        ASSERT_TRUE(proc_cmdline_key_streq("", ""));
        ASSERT_TRUE(proc_cmdline_key_streq("a", "a"));
        ASSERT_FALSE(proc_cmdline_key_streq("", "a"));
        ASSERT_FALSE(proc_cmdline_key_streq("a", ""));
        ASSERT_TRUE(proc_cmdline_key_streq("a", "a"));
        ASSERT_FALSE(proc_cmdline_key_streq("a", "b"));
        ASSERT_TRUE(proc_cmdline_key_streq("x-y-z", "x-y-z"));
        ASSERT_TRUE(proc_cmdline_key_streq("x-y-z", "x_y_z"));
        ASSERT_TRUE(proc_cmdline_key_streq("x-y-z", "x-y_z"));
        ASSERT_TRUE(proc_cmdline_key_streq("x-y-z", "x_y-z"));
        ASSERT_TRUE(proc_cmdline_key_streq("x_y-z", "x-y_z"));
        ASSERT_FALSE(proc_cmdline_key_streq("x_y-z", "x-z_z"));
}

TEST(proc_cmdline_key_startswith) {
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("", ""));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("x", ""));
        ASSERT_NULL(proc_cmdline_key_startswith("", "x"));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("x", "x"));
        ASSERT_NULL(proc_cmdline_key_startswith("x", "y"));
        ASSERT_NULL(proc_cmdline_key_startswith("foo-bar", "quux"));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("foo-bar", "foo"));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("foo-bar", "foo-bar"));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("foo-bar", "foo_bar"));
        ASSERT_NOT_NULL(proc_cmdline_key_startswith("foo-bar", "foo_"));
        ASSERT_NULL(proc_cmdline_key_startswith("foo-bar", "foo_xx"));
}

#define test_proc_cmdline_filter_pid1_args_one(nulstr, expected)                             \
        ({                                                                                   \
                _cleanup_strv_free_ char **a = NULL, **b = NULL;                             \
                const char s[] = (nulstr);                                                   \
                                                                                             \
                /* This emulates pid_get_cmdline_strv(). */                                  \
                ASSERT_NOT_NULL(a = strv_parse_nulstr_full(s, ELEMENTSOF(s),                 \
                                                           /* drop_trailing_nuls= */ true)); \
                ASSERT_OK(proc_cmdline_filter_pid1_args(a, &b));                             \
                ASSERT_STRV_EQ(b, expected);                                                 \
        })

TEST(proc_cmdline_filter_pid1_args) {
        test_proc_cmdline_filter_pid1_args_one("systemd\0",
                                               STRV_EMPTY);

        /* short option */
        test_proc_cmdline_filter_pid1_args_one("systemd\0"
                                               "-a\0"              /* unknown option */
                                               "-abc\0"            /* unknown options */
                                               "-h\0"              /* known option */
                                               "-hDbs\0"           /* known options */
                                               "-hsx\0"            /* mixed (known and unknown) options */
                                               "-z\0drop1\0"       /* option with argument */
                                               "-z\0-z\0accept1\0" /* the second -z is handled as argument */
                                               "-az\0drop2\0"      /* options with argument */
                                               "-za\0accept2\0"    /* options with argument */
                                               "-z\0--\0-x\0",     /* "--" is handled as argument */
                                               STRV_MAKE("accept1", "accept2"));

        /* long option */
        test_proc_cmdline_filter_pid1_args_one("systemd\0"
                                               "--unknown\0accept1\0"                /* unknown option */
                                               "--system\0accept2\0"                 /* no argument */
                                               "--log-level\0drop1\0"                /* required argument (separated with space) */
                                               "--log-level=drop2\0accept3\0"        /* required argument (concatenated with '=') */
                                               "--log-level\0--log-level\0accept4\0" /* the second "--log-level" is handled as argument */
                                               "--log-level\0--\0-x\0"               /* "--" is handled as argument */
                                               "--log-color\0--log-level\0drop3\0"   /* optional argument ("--log-level" is handled as another option) */
                                               "--log-color\0accept5\0"              /* optional argument (separated with space) */
                                               "--log-color=drop4\0accept6\0"        /* optional argument (concatenated with '=') */
                                               "--introspect-cli\0accept7\0"         /* no argument */
                                               "--log-color\0--\0"                   /* "--" is _not_ handled as argument, and remaining strings are accepted */
                                               "remaining\0-x\0--foo\0",
                                               STRV_MAKE("accept1", "accept2", "accept3", "accept4", "accept5", "accept6", "accept7", "remaining", "-x", "--foo"));

        /* test for "--" */
        test_proc_cmdline_filter_pid1_args_one("systemd\0"
                                               "-a\0"
                                               "--dropped\0"
                                               "--\0"          /* remaining strings are accepted */
                                               "-x\0"
                                               "-abc\0"
                                               "--hoge\0"
                                               "accepted\0",
                                               STRV_MAKE("-x", "-abc", "--hoge", "accepted"));

        /* test for space */
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
