/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "util.h"

static void test_config_parse_path_one(const char *rvalue, const char *expected) {
        _cleanup_free_ char *path = NULL;

        assert_se(config_parse_path("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &path, NULL) >= 0);
        assert_se(streq_ptr(expected, path));
}

static void test_config_parse_log_level_one(const char *rvalue, int expected) {
        int log_level = 0;

        assert_se(config_parse_log_level("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &log_level, NULL) >= 0);
        assert_se(expected == log_level);
}

static void test_config_parse_log_facility_one(const char *rvalue, int expected) {
        int log_facility = 0;

        assert_se(config_parse_log_facility("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &log_facility, NULL) >= 0);
        assert_se(expected == log_facility);
}

static void test_config_parse_iec_size_one(const char *rvalue, size_t expected) {
        size_t iec_size = 0;

        assert_se(config_parse_iec_size("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &iec_size, NULL) >= 0);
        assert_se(expected == iec_size);
}

static void test_config_parse_si_uint64_one(const char *rvalue, uint64_t expected) {
        uint64_t si_uint64 = 0;

        assert_se(config_parse_si_uint64("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &si_uint64, NULL) >= 0);
        assert_se(expected == si_uint64);
}

static void test_config_parse_int_one(const char *rvalue, int expected) {
        int v = -1;

        assert_se(config_parse_int("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL) >= 0);
        assert_se(expected == v);
}

static void test_config_parse_unsigned_one(const char *rvalue, unsigned expected) {
        unsigned v = 0;

        assert_se(config_parse_unsigned("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL) >= 0);
        assert_se(expected == v);
}

static void test_config_parse_strv_one(const char *rvalue, char **expected) {
        _cleanup_strv_free_ char **strv = NULL;

        assert_se(config_parse_strv("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &strv, NULL) >= 0);
        assert_se(strv_equal(expected, strv));
}

static void test_config_parse_mode_one(const char *rvalue, mode_t expected) {
        mode_t v = 0;

        assert_se(config_parse_mode("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL) >= 0);
        assert_se(expected == v);
}

static void test_config_parse_sec_one(const char *rvalue, usec_t expected) {
        usec_t v = 0;

        assert_se(config_parse_sec("unit", "filename", 1, "section", 1, "lvalue", 0, rvalue, &v, NULL) >= 0);
        assert_se(expected == v);
}

static void test_config_parse_nsec_one(const char *rvalue, nsec_t expected) {
        nsec_t v = 0;

        assert_se(config_parse_nsec("unit", "filename", 1, "nsection", 1, "lvalue", 0, rvalue, &v, NULL) >= 0);
        assert_se(expected == v);
}

static void test_config_parse_path(void) {
        test_config_parse_path_one("/path", "/path");
        test_config_parse_path_one("/path//////////", "/path");
        test_config_parse_path_one("///path/foo///bar////bar//", "/path/foo/bar/bar");
        test_config_parse_path_one("/path//./////hogehoge///.", "/path/hogehoge");
        test_config_parse_path_one("/path/\xc3\x80", "/path/\xc3\x80");

        test_config_parse_path_one("not_absolute/path", NULL);
        test_config_parse_path_one("/path/\xc3\x7f", NULL);
}

static void test_config_parse_log_level(void) {
        test_config_parse_log_level_one("debug", LOG_DEBUG);
        test_config_parse_log_level_one("info", LOG_INFO);

        test_config_parse_log_level_one("garbage", 0);
}

static void test_config_parse_log_facility(void) {
        test_config_parse_log_facility_one("mail", LOG_MAIL);
        test_config_parse_log_facility_one("user", LOG_USER);

        test_config_parse_log_facility_one("garbage", 0);
}

static void test_config_parse_iec_size(void) {
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

static void test_config_parse_si_uint64(void) {
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

static void test_config_parse_int(void) {
        test_config_parse_int_one("1024", 1024);
        test_config_parse_int_one("-1024", -1024);
        test_config_parse_int_one("0", 0);

        test_config_parse_int_one("99999999999999999999999999999999999999999999999999999999", -1);
        test_config_parse_int_one("-99999999999999999999999999999999999999999999999999999999", -1);
        test_config_parse_int_one("1G", -1);
        test_config_parse_int_one("garbage", -1);
}

static void test_config_parse_unsigned(void) {
        test_config_parse_unsigned_one("10241024", 10241024);
        test_config_parse_unsigned_one("1024", 1024);
        test_config_parse_unsigned_one("0", 0);

        test_config_parse_unsigned_one("99999999999999999999999999999999999999999999999999999999", 0);
        test_config_parse_unsigned_one("1G", 0);
        test_config_parse_unsigned_one("garbage", 0);
        test_config_parse_unsigned_one("1000garbage", 0);
}

static void test_config_parse_strv(void) {
        test_config_parse_strv_one("", STRV_MAKE_EMPTY);
        test_config_parse_strv_one("foo", STRV_MAKE("foo"));
        test_config_parse_strv_one("foo bar foo", STRV_MAKE("foo", "bar", "foo"));
        test_config_parse_strv_one("\"foo bar\" foo", STRV_MAKE("foo bar", "foo"));
        test_config_parse_strv_one("\xc3\x80", STRV_MAKE("\xc3\x80"));
        test_config_parse_strv_one("\xc3\x7f", STRV_MAKE("\xc3\x7f"));
}

static void test_config_parse_mode(void) {
        test_config_parse_mode_one("777", 0777);
        test_config_parse_mode_one("644", 0644);

        test_config_parse_mode_one("-777", 0);
        test_config_parse_mode_one("999", 0);
        test_config_parse_mode_one("garbage", 0);
        test_config_parse_mode_one("777garbage", 0);
        test_config_parse_mode_one("777 garbage", 0);
}

static void test_config_parse_sec(void) {
        test_config_parse_sec_one("1", 1 * USEC_PER_SEC);
        test_config_parse_sec_one("1s", 1 * USEC_PER_SEC);
        test_config_parse_sec_one("100ms", 100 * USEC_PER_MSEC);
        test_config_parse_sec_one("5min 20s", 5 * 60 * USEC_PER_SEC + 20 * USEC_PER_SEC);

        test_config_parse_sec_one("-1", 0);
        test_config_parse_sec_one("10foo", 0);
        test_config_parse_sec_one("garbage", 0);
}

static void test_config_parse_nsec(void) {
        test_config_parse_nsec_one("1", 1);
        test_config_parse_nsec_one("1s", 1 * NSEC_PER_SEC);
        test_config_parse_nsec_one("100ms", 100 * NSEC_PER_MSEC);
        test_config_parse_nsec_one("5min 20s", 5 * 60 * NSEC_PER_SEC + 20 * NSEC_PER_SEC);

        test_config_parse_nsec_one("-1", 0);
        test_config_parse_nsec_one("10foo", 0);
        test_config_parse_nsec_one("garbage", 0);
}

static void test_config_parse_iec_uint64(void) {
        uint64_t offset = 0;
        assert_se(config_parse_iec_uint64(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4M", &offset, NULL) == 0);
        assert_se(offset == 4 * 1024 * 1024);

        assert_se(config_parse_iec_uint64(NULL, "/this/file", 11, "Section", 22, "Size", 0, "4.5M", &offset, NULL) == 0);
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

static void test_config_parse(unsigned i, const char *s) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-conf-parser.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *setting1 = NULL;
        int r;

        const ConfigTableItem items[] = {
                { "Section", "setting1",  config_parse_string,   0, &setting1},
                {}
        };

        log_info("== %s[%i] ==", __func__, i);

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
                         usec_t *ret_mtime)
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
                assert_se(r == 0);
                assert_se(streq(setting1, "1"));
                break;

        case 5 ... 10:
                assert_se(r == 0);
                assert_se(streq(setting1, "1 2 3"));
                break;

        case 11:
                assert_se(r == 0);
                assert_se(streq(setting1, "1\\\\ \\\\2"));
                break;

        case 12:
                assert_se(r == 0);
                assert_se(streq(setting1, x1000("ABCD")));
                break;

        case 13 ... 14:
                assert_se(r == 0);
                assert_se(streq(setting1, x1000("ABCD") " foobar"));
                break;

        case 15 ... 16:
                assert_se(r == -ENOBUFS);
                assert_se(setting1 == NULL);
                break;

        case 17:
                assert_se(r == 0);
                assert_se(streq(setting1, "2"));
                break;
        }
}

static void setup_conf_files(const char *root, bool is_main, char **conf_files, char ***ret_conf_dirs) {
        char **path;

        /* If 'is_main' is true then 'conf_files' should only contains an entry
         * for the main conf file. */
        if (is_main)
                assert_se(strv_length(conf_files) <= 1);

        STRV_FOREACH(path, conf_files) {
                _cleanup_free_ char *abspath = NULL;
                _cleanup_fclose_ FILE *f = NULL;

                abspath = path_join(root, *path);
                assert_se(abspath);

                (void) mkdir_parents(abspath, 0755);

                f = fopen(abspath, "w");
                assert_se(f);
                fprintf(f,
                        "[Section]\n"
                        "name=%s\n",
                        *path);

                if (!is_main)
                        fprintf(f,
                                "%s=%s\n",
                                startswith(basename(*path), "__") ? "early" : "late",
                                *path);

                if (ret_conf_dirs) {
                        char *d;

                        assert_se((d = dirname_malloc(abspath)));
                        assert_se(strv_push(ret_conf_dirs, d) == 0);
                }
        }

        if (ret_conf_dirs) {
                strv_uniq(*ret_conf_dirs);
                strv_sort(*ret_conf_dirs);
        }
}

static void test_config_parse_many_one(bool nulstr, const char *main, char **conf_files,
                                       const char *name, const char *early, const char *late) {

        _cleanup_free_ char *parsed_name = NULL, *parsed_early = NULL, *parsed_late = NULL;
        _cleanup_strv_free_ char **conf_dirs = NULL;
        _cleanup_free_ char *conf_dirs_nulstr = NULL;
        char *conf_file;
        char *tmp_dir;
        size_t size;
        int r;

        const ConfigTableItem items[] = {
                { "Section", "name",  config_parse_string, 0, &parsed_name},
                { "Section", "late",  config_parse_string, 0, &parsed_late},
                { "Section", "early", config_parse_string, 0, &parsed_early},
        };

        tmp_dir = strdupa("/tmp/test-conf-parser-XXXXXX");
        assert_se(mkdtemp(tmp_dir));

        setup_conf_files(tmp_dir, true, STRV_MAKE(main), NULL);
        setup_conf_files(tmp_dir, false, conf_files, &conf_dirs);

        conf_file = main ? strjoina(tmp_dir, "/", main) : NULL;

        if (nulstr) {
                r = strv_make_nulstr(conf_dirs, &conf_dirs_nulstr, &size);
                assert_se(r == 0);

                r = config_parse_many_nulstr(conf_file, conf_dirs_nulstr,
                                             "Section\0",
                                             config_item_table_lookup, items,
                                             CONFIG_PARSE_WARN,
                                             NULL,
                                             NULL);
        } else {
                r = config_parse_many(conf_file, (const char * const*) conf_dirs, "",
                                      "Section\0",
                                      config_item_table_lookup, items,
                                      CONFIG_PARSE_WARN,
                                      NULL,
                                      NULL);
        }

        assert_se(r == 0);
        assert_se((!name && !parsed_name) || streq(name, parsed_name));
        assert_se((!late && !parsed_late) || streq(late, parsed_late));
        assert_se((!early && !parsed_early) || streq(early, parsed_early));

        assert_se(rm_rf(tmp_dir, REMOVE_ROOT|REMOVE_PHYSICAL) == 0);
}

static void test_config_parse_many(bool nulstr) {
        test_config_parse_many_one(nulstr, NULL, NULL, NULL, NULL, NULL);

        test_config_parse_many_one(nulstr,
                                   "dir/main.conf", NULL,
                                   "dir/main.conf", NULL, NULL);

        test_config_parse_many_one(nulstr,
                                   NULL, STRV_MAKE("dir1/50-foo.conf"),
                                   "dir1/50-foo.conf", NULL, "dir1/50-foo.conf");

        test_config_parse_many_one(nulstr,
                                   NULL, STRV_MAKE("dir1/__50-foo.conf"),
                                   "dir1/__50-foo.conf", "dir1/__50-foo.conf", NULL);

        test_config_parse_many_one(nulstr,
                                   NULL, STRV_MAKE("dir1/10-foo.conf", "dir1/50-bar.conf"),
                                   "dir1/50-bar.conf", NULL, "dir1/50-bar.conf");

        test_config_parse_many_one(nulstr,
                                   NULL, STRV_MAKE("dir1/50-foo.conf", "dir2/10-bar.conf"),
                                   "dir1/50-foo.conf", NULL, "dir1/50-foo.conf");

        test_config_parse_many_one(nulstr,
                                   NULL, STRV_MAKE("dir1/10-foo.conf", "dir2/10-foo.conf"),
                                   "dir1/10-foo.conf", NULL, "dir1/10-foo.conf");

        /* Early conf files should never override the main one whatever their
         * priority/location. */
        test_config_parse_many_one(nulstr,
                                   "dir/10-main.conf",
                                   STRV_MAKE("dir1/__10-foo.conf", "dir2/__99-foo.conf"),
                                   "dir/10-main.conf", "dir2/__99-foo.conf", NULL);

        /* Late conf files always take precendence over the early conf files
         * and the main one. */
        test_config_parse_many_one(nulstr,
                                   "dir/50-main.conf", STRV_MAKE("dir1/10-foo.conf"),
                                   "dir1/10-foo.conf", NULL, "dir1/10-foo.conf");

        test_config_parse_many_one(nulstr,
                                   "dir/10-main.conf",
                                   STRV_MAKE("dir1/__10-foo.conf", "dir2/__99-foo.conf",
                                             "dir2/10-foo.conf"),
                                   "dir2/10-foo.conf", "dir2/__99-foo.conf", "dir2/10-foo.conf");
}

int main(int argc, char **argv) {
        unsigned i;

        log_parse_environment();
        log_open();

        test_config_parse_path();
        test_config_parse_log_level();
        test_config_parse_log_facility();
        test_config_parse_iec_size();
        test_config_parse_si_uint64();
        test_config_parse_int();
        test_config_parse_unsigned();
        test_config_parse_strv();
        test_config_parse_mode();
        test_config_parse_sec();
        test_config_parse_nsec();
        test_config_parse_iec_uint64();

        for (i = 0; i < ELEMENTSOF(config_file); i++)
                test_config_parse(i, config_file[i]);

        test_config_parse_many(true);
        test_config_parse_many(false);

        return 0;
}
