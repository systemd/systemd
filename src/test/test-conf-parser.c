/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fd-util.h"
#include "fs-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

static void test_config_parse_path_one(const char *rvalue, const char *expected) {
        _cleanup_free_ char *path = NULL;

        ASSERT_OK(config_parse_path("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &path, NULL));
        ASSERT_STREQ(expected, path);
}

static void test_config_parse_log_level_one(const char *rvalue, int expected) {
        int log_level = 0;

        ASSERT_OK(config_parse_log_level("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &log_level, NULL));
        ASSERT_EQ(expected, log_level);
}

static void test_config_parse_log_facility_one(const char *rvalue, int expected) {
        int log_facility = 0;

        ASSERT_OK(config_parse_log_facility("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &log_facility, NULL));
        ASSERT_EQ(expected, log_facility);
}

static void test_config_parse_iec_size_one(const char *rvalue, size_t expected) {
        size_t iec_size = 0;

        ASSERT_OK(config_parse_iec_size("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &iec_size, NULL));
        ASSERT_EQ(expected, iec_size);
}

static void test_config_parse_si_uint64_one(const char *rvalue, uint64_t expected) {
        uint64_t si_uint64 = 0;

        ASSERT_OK(config_parse_si_uint64("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &si_uint64, NULL));
        ASSERT_EQ(expected, si_uint64);
}

static void test_config_parse_int_one(const char *rvalue, int expected) {
        int v = -1;

        ASSERT_OK(config_parse_int("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

static void test_config_parse_unsigned_one(const char *rvalue, unsigned expected) {
        unsigned v = 0;

        ASSERT_OK(config_parse_unsigned("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

static void test_config_parse_strv_one(const char *rvalue, bool filter_duplicates, char **expected) {
        _cleanup_strv_free_ char **strv = NULL;

        ASSERT_OK(config_parse_strv("unit", "filename", 1, "section", 1, "lvalue", filter_duplicates, rvalue, &strv, NULL));
        ASSERT_TRUE(strv_equal(expected, strv));
}

static void test_config_parse_mode_one(const char *rvalue, mode_t expected) {
        mode_t v = 0;

        ASSERT_OK(config_parse_mode("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

static void test_config_parse_sec_one(const char *rvalue, usec_t expected) {
        usec_t v = 0;

        ASSERT_OK(config_parse_sec("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

static void test_config_parse_nsec_one(const char *rvalue, nsec_t expected) {
        nsec_t v = 0;

        ASSERT_OK(config_parse_nsec("unit", "filename", 1, "nsection", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

static void test_config_parse_iec_uint64_one(const char *rvalue, uint64_t expected) {
        uint64_t v = 0;

        ASSERT_OK(config_parse_iec_uint64("unit", "filename", 1, "nsection", 1, "lvalue", 0, rvalue, &v, NULL));
        ASSERT_EQ(expected, v);
}

TEST(config_parse_path) {
        test_config_parse_path_one("/path", "/path");
        test_config_parse_path_one("/path//////////", "/path");
        test_config_parse_path_one("///path/foo///bar////bar//", "/path/foo/bar/bar");
        test_config_parse_path_one("/path//./////hogehoge///.", "/path/hogehoge");
        test_config_parse_path_one("/path/\xc3\x80", "/path/\xc3\x80");

        test_config_parse_path_one("not_absolute/path", NULL);
        test_config_parse_path_one("/path/\xc3\x7f", NULL);
}

TEST(config_parse_log_level) {
        test_config_parse_log_level_one("debug", LOG_DEBUG);
        test_config_parse_log_level_one("info", LOG_INFO);

        test_config_parse_log_level_one("garbage", 0);
}

TEST(config_parse_log_facility) {
        test_config_parse_log_facility_one("mail", LOG_MAIL);
        test_config_parse_log_facility_one("user", LOG_USER);

        test_config_parse_log_facility_one("garbage", 0);
}

TEST(config_parse_iec_size) {
        test_config_parse_iec_size_one("1024", 1024);
        test_config_parse_iec_size_one("2K", 2048);
        test_config_parse_iec_size_one("10M", 10 * 1024 * 1024);
        test_config_parse_iec_size_one("1G", 1 * 1024 * 1024 * 1024);
        test_config_parse_iec_size_one("0G", 0);
        test_config_parse_iec_size_one("0", 0);

        test_config_parse_iec_size_one("-982", 0);
        test_config_parse_iec_size_one("49874444198739873000000G", 0);
        test_config_parse_iec_size_one("garbage", 0);
}

TEST(config_parse_si_uint64) {
        test_config_parse_si_uint64_one("1024", 1024);
        test_config_parse_si_uint64_one("2K", 2000);
        test_config_parse_si_uint64_one("10M", 10 * 1000 * 1000);
        test_config_parse_si_uint64_one("1G", 1 * 1000 * 1000 * 1000);
        test_config_parse_si_uint64_one("0G", 0);
        test_config_parse_si_uint64_one("0", 0);

        test_config_parse_si_uint64_one("-982", 0);
        test_config_parse_si_uint64_one("49874444198739873000000G", 0);
        test_config_parse_si_uint64_one("garbage", 0);
}

TEST(config_parse_int) {
        test_config_parse_int_one("1024", 1024);
        test_config_parse_int_one("-1024", -1024);
        test_config_parse_int_one("0", 0);

        test_config_parse_int_one("99999999999999999999999999999999999999999999999999999999", -1);
        test_config_parse_int_one("-99999999999999999999999999999999999999999999999999999999", -1);
        test_config_parse_int_one("1G", -1);
        test_config_parse_int_one("garbage", -1);
}

TEST(config_parse_unsigned) {
        test_config_parse_unsigned_one("10241024", 10241024);
        test_config_parse_unsigned_one("1024", 1024);
        test_config_parse_unsigned_one("0", 0);

        test_config_parse_unsigned_one("99999999999999999999999999999999999999999999999999999999", 0);
        test_config_parse_unsigned_one("1G", 0);
        test_config_parse_unsigned_one("garbage", 0);
        test_config_parse_unsigned_one("1000garbage", 0);
}

TEST(config_parse_strv) {
        test_config_parse_strv_one("", false, STRV_MAKE_EMPTY);
        test_config_parse_strv_one("foo", false, STRV_MAKE("foo"));
        test_config_parse_strv_one("foo bar foo", false, STRV_MAKE("foo", "bar", "foo"));
        test_config_parse_strv_one("\"foo bar\" foo", false, STRV_MAKE("foo bar", "foo"));
        test_config_parse_strv_one("\xc3\x80", false, STRV_MAKE("\xc3\x80"));
        test_config_parse_strv_one("\xc3\x7f", false, STRV_MAKE("\xc3\x7f"));

        test_config_parse_strv_one("", true, STRV_MAKE_EMPTY);
        test_config_parse_strv_one("foo", true, STRV_MAKE("foo"));
        test_config_parse_strv_one("foo bar foo", true, STRV_MAKE("foo", "bar"));
        test_config_parse_strv_one("\"foo bar\" foo", true, STRV_MAKE("foo bar", "foo"));
        test_config_parse_strv_one("\xc3\x80", true, STRV_MAKE("\xc3\x80"));
        test_config_parse_strv_one("\xc3\x7f", true, STRV_MAKE("\xc3\x7f"));
}

TEST(config_parse_mode) {
        test_config_parse_mode_one("777", 0777);
        test_config_parse_mode_one("644", 0644);

        test_config_parse_mode_one("-777", 0);
        test_config_parse_mode_one("999", 0);
        test_config_parse_mode_one("garbage", 0);
        test_config_parse_mode_one("777garbage", 0);
        test_config_parse_mode_one("777 garbage", 0);
}

TEST(config_parse_sec) {
        test_config_parse_sec_one("1", 1 * USEC_PER_SEC);
        test_config_parse_sec_one("1s", 1 * USEC_PER_SEC);
        test_config_parse_sec_one("100ms", 100 * USEC_PER_MSEC);
        test_config_parse_sec_one("5min 20s", 5 * 60 * USEC_PER_SEC + 20 * USEC_PER_SEC);

        test_config_parse_sec_one("-1", 0);
        test_config_parse_sec_one("10foo", 0);
        test_config_parse_sec_one("garbage", 0);
}

TEST(config_parse_nsec) {
        test_config_parse_nsec_one("1", 1);
        test_config_parse_nsec_one("1s", 1 * NSEC_PER_SEC);
        test_config_parse_nsec_one("100ms", 100 * NSEC_PER_MSEC);
        test_config_parse_nsec_one("5min 20s", 5 * 60 * NSEC_PER_SEC + 20 * NSEC_PER_SEC);

        test_config_parse_nsec_one("-1", 0);
        test_config_parse_nsec_one("10foo", 0);
        test_config_parse_nsec_one("garbage", 0);
}

TEST(config_parse_iec_uint64) {
        test_config_parse_iec_uint64_one("4M", UINT64_C(4 * 1024 * 1024));
        test_config_parse_iec_uint64_one("4.5M", UINT64_C((4 * 1024 + 512) * 1024));
}

#define x10(x) x x x x x x x x x x
#define x100(x) x10(x10(x))
#define x1000(x) x10(x100(x))

static const char* const config_file[] = {
        "[Section]\n"
        "setting1=1\n",

        "[Section]\n"
        "setting1=1",        /* no terminating newline */

        "\n\n\n\n[Section]\n\n\n"
        "setting1=1",        /* some whitespace, no terminating newline */

        "[Section]\n"
        "[Section]\n"
        "setting1=1\n"
        "setting1=    2 \t\n"
        "setting1=    1\n",  /* repeated settings */

        "[Section]\n"
        "[Section]\n"
        "setting1=1\n"
        "setting1=2\\\n"
        "   \n"              /* empty line breaks continuation */
        "setting1=1\n",      /* repeated settings */

        "[Section]\n"
        "setting1=1\\\n"     /* normal continuation */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "#hogehoge\\\n"      /* continuation is ignored in comment */
        "setting1=1\\\n"     /* normal continuation */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "setting1=1\\\n"     /* normal continuation */
        "#hogehoge\\\n"      /* commented out line in continuation is ignored */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "   #hogehoge\\\n"   /* whitespaces before comments */
        "   setting1=1\\\n"  /* whitespaces before key */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "   setting1=1\\\n"  /* whitespaces before key */
        "   #hogehoge\\\n"   /* commented out line prefixed with whitespaces in continuation */
        "2\\\n"
        "3\n",

        "[Section]\n"
        "setting1=1\\\n"     /* continuation with extra trailing backslash at the end */
        "2\\\n"
        "3\\\n",

        "[Section]\n"
        "setting1=1\\\\\\\n" /* continuation with trailing escape symbols */
        "\\\\2\n",           /* note that C requires one level of escaping, so the
                              * parser gets "…1 BS BS BS NL BS BS 2 NL", which
                              * it translates into "…1 BS BS SP BS BS 2" */

        "\n[Section]\n\n"
        "setting1="          /* a line above LINE_MAX length */
        x1000("ABCD")
        "\n",

        "[Section]\n"
        "setting1="          /* a line above LINE_MAX length, with continuation */
        x1000("ABCD") "\\\n"
        "foobar",

        "[Section]\n"
        "setting1="          /* a line above LINE_MAX length, with continuation */
        x1000("ABCD") "\\\n" /* and an extra trailing backslash */
        "foobar\\\n",

        "[Section]\n"
        "setting1="          /* a line above the allowed limit: 9 + 1050000 + 1 */
        x1000(x1000("x") x10("abcde")) "\n",

        "[Section]\n"
        "setting1="          /* many continuation lines, together above the limit */
        x1000(x1000("x") x10("abcde") "\\\n") "xxx",

        "[Section]\n"
        "setting1=2\n"
        "[NoWarnSection]\n"
        "setting1=3\n"
        "[WarnSection]\n"
        "setting1=3\n"
        "[X-Section]\n"
        "setting1=3\n",
};

static void test_config_parse_one(unsigned i, const char *s) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-conf-parser.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *setting1 = NULL;
        int r;

        const ConfigTableItem items[] = {
                { "Section", "setting1",  config_parse_string,   0, &setting1},
                {}
        };

        log_info("== %s[%u] ==", __func__, i);

        assert_se(fmkostemp_safe(name, "r+", &f) == 0);
        assert_se(fwrite(s, strlen(s), 1, f) == 1);
        rewind(f);

        /*
        int config_parse(const char *unit,
                         const char *filename,
                         FILE *f,
                         const char *sections,
                         ConfigItemLookup lookup,
                         const void *table,
                         ConfigParseFlags flags,
                         void *userdata,
                         struct stat *ret_stat);
        */

        r = config_parse(NULL, name, f,
                         "Section\0"
                         "-NoWarnSection\0",
                         config_item_table_lookup, items,
                         CONFIG_PARSE_WARN,
                         NULL,
                         NULL);

        switch (i) {
        case 0 ... 4:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, "1");
                break;

        case 5 ... 10:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, "1 2 3");
                break;

        case 11:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, "1\\\\ \\\\2");
                break;

        case 12:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, x1000("ABCD"));
                break;

        case 13 ... 14:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, x1000("ABCD") " foobar");
                break;

        case 15 ... 16:
                assert_se(r == -ENOBUFS);
                ASSERT_NULL(setting1);
                break;

        case 17:
                assert_se(r == 1);
                ASSERT_STREQ(setting1, "2");
                break;
        }
}

TEST(config_parse) {
        for (unsigned i = 0; i < ELEMENTSOF(config_file); i++)
                test_config_parse_one(i, config_file[i]);
}

TEST(config_parse_standard_file_with_dropins_full) {
        _cleanup_(rm_rf_physical_and_freep) char *root = NULL;
        _cleanup_close_ int rfd = -EBADF;
        int r;

        ASSERT_OK(rfd = mkdtemp_open("/tmp/test-config-parse-XXXXXX", 0, &root));
        assert_se(mkdir_p_root(root, "/etc/kernel/install.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/run/kernel/install.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/usr/lib/kernel/install.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/usr/local/lib/kernel/install.conf.d", UID_INVALID, GID_INVALID, 0755));

        assert_se(write_string_file_at(rfd, "usr/lib/kernel/install.conf",         /* this one is ignored */
                                       "A=!!!", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "usr/local/lib/kernel/install.conf",
                                       "A=aaa", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "usr/local/lib/kernel/install.conf.d/drop1.conf",
                                       "B=bbb", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "usr/local/lib/kernel/install.conf.d/drop2.conf",
                                       "C=c1", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "usr/lib/kernel/install.conf.d/drop2.conf",   /* this one is ignored */
                                       "C=c2", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "run/kernel/install.conf.d/drop3.conf",
                                       "D=ddd", WRITE_STRING_FILE_CREATE) == 0);
        assert_se(write_string_file_at(rfd, "etc/kernel/install.conf.d/drop4.conf",
                                       "E=eee", WRITE_STRING_FILE_CREATE) == 0);

        _cleanup_free_ char *A = NULL, *B = NULL, *C = NULL, *D = NULL, *E = NULL, *F = NULL;
        _cleanup_strv_free_ char **dropins = NULL;

        const ConfigTableItem items[] = {
                { NULL, "A",  config_parse_string,   0, &A},
                { NULL, "B",  config_parse_string,   0, &B},
                { NULL, "C",  config_parse_string,   0, &C},
                { NULL, "D",  config_parse_string,   0, &D},
                { NULL, "E",  config_parse_string,   0, &E},
                { NULL, "F",  config_parse_string,   0, &F},
                {}
        };

        r = config_parse_standard_file_with_dropins_full(
                        root, "kernel/install.conf",
                        /* sections= */ NULL,
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ &dropins);
        assert_se(r >= 0);
        ASSERT_STREQ(A, "aaa");
        ASSERT_STREQ(B, "bbb");
        ASSERT_STREQ(C, "c1");
        ASSERT_STREQ(D, "ddd");
        ASSERT_STREQ(E, "eee");
        ASSERT_STREQ(F, NULL);

        A = mfree(A);
        B = mfree(B);
        C = mfree(C);
        D = mfree(D);
        E = mfree(E);

        assert_se(strv_length(dropins) == 4);

        /* Make sure that we follow symlinks */
        assert_se(mkdir_p_root(root, "/etc/kernel/install2.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/run/kernel/install2.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/usr/lib/kernel/install2.conf.d", UID_INVALID, GID_INVALID, 0755));
        assert_se(mkdir_p_root(root, "/usr/local/lib/kernel/install2.conf.d", UID_INVALID, GID_INVALID, 0755));

        /* (Those symlinks are only useful relative to <root>. */
        assert_se(symlinkat("/usr/lib/kernel/install.conf", rfd, "usr/lib/kernel/install2.conf") == 0);
        assert_se(symlinkat("/usr/local/lib/kernel/install.conf", rfd, "usr/local/lib/kernel/install2.conf") == 0);
        assert_se(symlinkat("/usr/local/lib/kernel/install.conf.d/drop1.conf", rfd, "usr/local/lib/kernel/install2.conf.d/drop1.conf") == 0);
        assert_se(symlinkat("/usr/local/lib/kernel/install.conf.d/drop2.conf", rfd, "usr/local/lib/kernel/install2.conf.d/drop2.conf") == 0);
        assert_se(symlinkat("/usr/lib/kernel/install.conf.d/drop2.conf", rfd, "usr/lib/kernel/install2.conf.d/drop2.conf") == 0);
        assert_se(symlinkat("/run/kernel/install.conf.d/drop3.conf", rfd, "run/kernel/install2.conf.d/drop3.conf") == 0);
        assert_se(symlinkat("/etc/kernel/install.conf.d/drop4.conf", rfd, "etc/kernel/install2.conf.d/drop4.conf") == 0);

        r = config_parse_standard_file_with_dropins_full(
                        root, "kernel/install2.conf",
                        /* sections= */ NULL,
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ NULL);
        assert_se(r >= 0);
        ASSERT_STREQ(A, "aaa");
        ASSERT_STREQ(B, "bbb");
        ASSERT_STREQ(C, "c1");
        ASSERT_STREQ(D, "ddd");
        ASSERT_STREQ(E, "eee");
        ASSERT_STREQ(F, NULL);
}

DEFINE_TEST_MAIN(LOG_INFO);
