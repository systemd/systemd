/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-file.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "macro.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

/* In case of repeating keys, later entries win. */

#define env_file_1                              \
        "a=a\n"                                 \
        "a=b\n"                                 \
        "a=b\n"                                 \
        "a=a\n"                                 \
        "b=b\\\n"                               \
        "c\n"                                   \
        "d= d\\\n"                              \
        "e  \\\n"                               \
        "f  \n"                                 \
        "g=g\\ \n"                              \
        "h= ąęół\\ śćńźżμ \n"                   \
        "i=i\\"

#define env_file_2                              \
        "a=a\\\n"

#define env_file_3 \
        "#SPAMD_ARGS=\"-d --socketpath=/var/lib/bulwark/spamd \\\n" \
        "#--nouser-config                                     \\\n" \
        "normal1=line\\\n"                                           \
        "111\n"                                                     \
        ";normal=ignored                                      \\\n" \
        "normal2=line222\n"                                          \
        "normal ignored                                       \\\n"

#define env_file_4                              \
        "# Generated\n"                         \
        "\n"                                    \
        "HWMON_MODULES=\"coretemp f71882fg\"\n" \
        "\n"                                    \
        "# For compatibility reasons\n"         \
        "\n"                                    \
        "MODULE_0=coretemp\n"                   \
        "MODULE_1=f71882fg"

#define env_file_5                              \
        "a=\n"                                  \
        "b="

#define env_file_6                              \
        "a=\\ \\n \\t \\x \\y \\' \n"           \
        "b= \\$'                  \n"           \
        "c= ' \\n\\t\\$\\`\\\\\n"               \
        "'   \n"                                \
        "d= \" \\n\\t\\$\\`\\\\\n"              \
        "\"   \n"

TEST(load_env_file_1) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_1) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "a=a");
        ASSERT_STREQ(data[1], "b=bc");
        ASSERT_STREQ(data[2], "d=de  f");
        ASSERT_STREQ(data[3], "g=g ");
        ASSERT_STREQ(data[4], "h=ąęół śćńźżμ");
        ASSERT_STREQ(data[5], "i=i");
        ASSERT_NULL(data[6]);
}

TEST(load_env_file_2) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_2) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "a=a");
        ASSERT_NULL(data[1]);
}

TEST(load_env_file_3) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_3) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "normal1=line111");
        ASSERT_STREQ(data[1], "normal2=line222");
        ASSERT_NULL(data[2]);
}

TEST(load_env_file_4) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_4) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "HWMON_MODULES=coretemp f71882fg");
        ASSERT_STREQ(data[1], "MODULE_0=coretemp");
        ASSERT_STREQ(data[2], "MODULE_1=f71882fg");
        ASSERT_NULL(data[3]);
}

TEST(load_env_file_5) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_5) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "a=");
        ASSERT_STREQ(data[1], "b=");
        ASSERT_NULL(data[2]);
}

TEST(load_env_file_6) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
        assert_se(write_tmpfile(name, env_file_6) == 0);

        _cleanup_strv_free_ char **data = NULL;
        assert_se(load_env_file(NULL, name, &data) == 0);
        ASSERT_STREQ(data[0], "a= n t x y '");
        ASSERT_STREQ(data[1], "b=$'");
        ASSERT_STREQ(data[2], "c= \\n\\t\\$\\`\\\\\n");
        ASSERT_STREQ(data[3], "d= \\n\\t$`\\\n");
        ASSERT_NULL(data[4]);
}

TEST(load_env_file_invalid_utf8) {
        /* Test out a couple of assignments where the key/value has an invalid
         * UTF-8 character ("noncharacter")
         *
         * See: https://en.wikipedia.org/wiki/Universal_Character_Set_characters#Non-characters
         */
        FOREACH_STRING(s,
                       "fo\ufffeo=bar",
                       "foo=b\uffffar",
                       "baz=hello world\ufffe") {
                _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-load-env-file.XXXXXX";
                assert_se(write_tmpfile(name, s) == 0);

                _cleanup_strv_free_ char **data = NULL;
                assert_se(load_env_file(NULL, name, &data) == -EINVAL);
                assert_se(!data);
        }
}

TEST(write_and_load_env_file) {
        /* Make sure that our writer, parser and the shell agree on what our env var files mean */

        FOREACH_STRING(v,
                       "obbardc-laptop",
                       "obbardc\\-laptop",
                       "obbardc-lap\\top",
                       "obbardc-lap\\top",
                       "obbardc-lap\\\\top",
                       "double\"quote",
                       "single\'quote",
                       "dollar$dollar",
                       "newline\nnewline") {
                _cleanup_(unlink_and_freep) char *p = NULL;
                _cleanup_strv_free_ char **l = NULL;
                _cleanup_free_ char *j = NULL, *w = NULL, *cmd = NULL, *from_shell = NULL;
                _cleanup_pclose_ FILE *f = NULL;
                size_t sz;

                assert_se(tempfn_random_child(NULL, NULL, &p) >= 0);

                assert_se(j = strjoin("TEST=", v));
                assert_se(write_env_file(AT_FDCWD, p, STRV_MAKE("# header 1", "", "# header 2"), STRV_MAKE(j)) >= 0);

                assert_se(cmd = strjoin(". ", p, " && /bin/echo -n \"$TEST\""));
                assert_se(f = popen(cmd, "re"));
                assert_se(read_full_stream(f, &from_shell, &sz) >= 0);
                assert_se(sz == strlen(v));
                ASSERT_STREQ(from_shell, v);

                assert_se(load_env_file(NULL, p, &l) >= 0);
                assert_se(strv_equal(l, STRV_MAKE(j)));

                assert_se(parse_env_file(NULL, p, "TEST", &w) >= 0);
                ASSERT_STREQ(w, v);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
