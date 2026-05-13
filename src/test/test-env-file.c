/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
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
                assert_se(write_env_file(AT_FDCWD, p, STRV_MAKE("# header 1", "", "# header 2"), STRV_MAKE(j), /* flags= */ 0) >= 0);

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

TEST(parse_env_file) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        FILE *f;
        _cleanup_free_ char *one = NULL, *two = NULL, *three = NULL, *four = NULL, *five = NULL,
                        *six = NULL, *seven = NULL, *eight = NULL, *nine = NULL, *ten = NULL,
                        *eleven = NULL, *twelve = NULL, *thirteen = NULL;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        unsigned k;

        ASSERT_OK(fmkostemp_safe(t, "w", &f));
        fputs("one=BAR   \n"
              "# comment\n"
              " # comment \n"
              " ; comment \n"
              "  two   =   bar    \n"
              "invalid line\n"
              "invalid line #comment\n"
              "three = \"333\n"
              "xxxx\"\n"
              "four = \'44\\\"44\'\n"
              "five = \"55\\\"55\" \"FIVE\" cinco   \n"
              "six = seis sechs\\\n"
              " sis\n"
              "seven=\"sevenval\" #nocomment\n"
              "eight=eightval #nocomment\n"
              "export nine=nineval\n"
              "ten=ignored\n"
              "ten=ignored\n"
              "ten=\n"
              "eleven=\\value\n"
              "twelve=\"\\value\"\n"
              "thirteen='\\value'", f);

        fflush(f);
        fclose(f);

        ASSERT_OK(load_env_file(NULL, t, &a));

        STRV_FOREACH(i, a)
                log_debug("Got: <%s>", *i);

        ASSERT_STREQ(a[0], "one=BAR");
        ASSERT_STREQ(a[1], "two=bar");
        ASSERT_STREQ(a[2], "three=333\nxxxx");
        ASSERT_STREQ(a[3], "four=44\\\"44");
        ASSERT_STREQ(a[4], "five=55\"55FIVEcinco");
        ASSERT_STREQ(a[5], "six=seis sechs sis");
        ASSERT_STREQ(a[6], "seven=sevenval#nocomment");
        ASSERT_STREQ(a[7], "eight=eightval #nocomment");
        ASSERT_STREQ(a[8], "export nine=nineval");
        ASSERT_STREQ(a[9], "ten=");
        ASSERT_STREQ(a[10], "eleven=value");
        ASSERT_STREQ(a[11], "twelve=\\value");
        ASSERT_STREQ(a[12], "thirteen=\\value");
        ASSERT_NULL(a[13]);

        strv_env_clean(a);

        k = 0;
        STRV_FOREACH(i, b) {
                log_debug("Got2: <%s>", *i);
                ASSERT_STREQ(*i, a[k++]);
        }

        ASSERT_OK(parse_env_file(NULL, t,
                                 "one", &one,
                                 "two", &two,
                                 "three", &three,
                                 "four", &four,
                                 "five", &five,
                                 "six", &six,
                                 "seven", &seven,
                                 "eight", &eight,
                                 "export nine", &nine,
                                 "ten", &ten,
                                 "eleven", &eleven,
                                 "twelve", &twelve,
                                 "thirteen", &thirteen));

        log_debug("one=[%s]", strna(one));
        log_debug("two=[%s]", strna(two));
        log_debug("three=[%s]", strna(three));
        log_debug("four=[%s]", strna(four));
        log_debug("five=[%s]", strna(five));
        log_debug("six=[%s]", strna(six));
        log_debug("seven=[%s]", strna(seven));
        log_debug("eight=[%s]", strna(eight));
        log_debug("export nine=[%s]", strna(nine));
        log_debug("ten=[%s]", strna(nine));
        log_debug("eleven=[%s]", strna(eleven));
        log_debug("twelve=[%s]", strna(twelve));
        log_debug("thirteen=[%s]", strna(thirteen));

        ASSERT_STREQ(one, "BAR");
        ASSERT_STREQ(two, "bar");
        ASSERT_STREQ(three, "333\nxxxx");
        ASSERT_STREQ(four, "44\\\"44");
        ASSERT_STREQ(five, "55\"55FIVEcinco");
        ASSERT_STREQ(six, "seis sechs sis");
        ASSERT_STREQ(seven, "sevenval#nocomment");
        ASSERT_STREQ(eight, "eightval #nocomment");
        ASSERT_STREQ(nine, "nineval");
        ASSERT_NULL(ten);
        ASSERT_STREQ(eleven, "value");
        ASSERT_STREQ(twelve, "\\value");
        ASSERT_STREQ(thirteen, "\\value");

        /* prepare a temporary file to write the environment to */
        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(fd = mkostemp_safe(p));

        ASSERT_OK(write_env_file(AT_FDCWD, p, /* headers= */ NULL, a, /* flags= */ 0));
        ASSERT_OK(load_env_file(NULL, p, &b));
}

static void test_one_shell_var(const char *file, const char *variable, const char *value) {
        _cleanup_free_ char *cmd = NULL, *from_shell = NULL;
        _cleanup_pclose_ FILE *f = NULL;
        size_t sz;

        ASSERT_NOT_NULL(cmd = strjoin(". ", file, " && /bin/echo -n \"$", variable, "\""));
        ASSERT_NOT_NULL(f = popen(cmd, "re"));
        ASSERT_OK(read_full_stream(f, &from_shell, &sz));
        ASSERT_EQ(sz, strlen(value));
        ASSERT_STREQ(from_shell, value);
}

TEST(parse_multiline_env_file) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        FILE *f;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        ASSERT_OK(fmkostemp_safe(t, "w", &f));
        fputs("one=BAR\\\n"
              "\\ \\ \\ \\ VAR\\\n"
              "\\\tGAR\n"
              "#comment\n"
              "two=\"bar\\\n"
              "    var\\\n"
              "\tgar\"\n"
              "#comment\n"
              "tri=\"bar \\\n"
              "    var \\\n"
              "\tgar \"\n", f);

        ASSERT_OK(fflush_and_check(f));
        fclose(f);

        test_one_shell_var(t, "one", "BAR    VAR\tGAR");
        test_one_shell_var(t, "two", "bar    var\tgar");
        test_one_shell_var(t, "tri", "bar     var \tgar ");

        ASSERT_OK(load_env_file(NULL, t, &a));

        STRV_FOREACH(i, a)
                log_debug("Got: <%s>", *i);

        ASSERT_STREQ(a[0], "one=BAR    VAR\tGAR");
        ASSERT_STREQ(a[1], "two=bar    var\tgar");
        ASSERT_STREQ(a[2], "tri=bar     var \tgar ");
        ASSERT_NULL(a[3]);

        _cleanup_close_ int fd = -EBADF;
        ASSERT_OK(fd = mkostemp_safe(p));

        ASSERT_OK(write_env_file(AT_FDCWD, p, /* headers= */ NULL, a, /* flags= */ 0));
        ASSERT_OK(load_env_file(NULL, p, &b));
}

TEST(merge_env_file) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK(fmkostemp_safe(t, "w", &f));

        ASSERT_OK(write_string_stream(f,
                                      "one=1   \n"
                                      "twelve=${one}2\n"
                                      "twentyone=2${one}\n"
                                      "one=2\n"
                                      "twentytwo=2${one}\n"
                                      "xxx_minus_three=$xxx - 3\n"
                                      "xxx=0x$one$one$one\n"
                                      "yyy=${one:-fallback}\n"
                                      "zzz=${one:+replacement}\n"
                                      "zzzz=${foobar:-${nothing}}\n"
                                      "zzzzz=${nothing:+${nothing}}\n"
                                      , WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK(merge_env_file(&a, NULL, t));
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_debug("Got: <%s>", *i);

        ASSERT_STREQ(a[0], "one=2");
        ASSERT_STREQ(a[1], "twelve=12");
        ASSERT_STREQ(a[2], "twentyone=21");
        ASSERT_STREQ(a[3], "twentytwo=22");
        ASSERT_STREQ(a[4], "xxx=0x222");
        ASSERT_STREQ(a[5], "xxx_minus_three= - 3");
        ASSERT_STREQ(a[6], "yyy=2");
        ASSERT_STREQ(a[7], "zzz=replacement");
        ASSERT_STREQ(a[8], "zzzz=");
        ASSERT_STREQ(a[9], "zzzzz=");
        ASSERT_NULL(a[10]);

        ASSERT_OK(merge_env_file(&a, NULL, t));
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_debug("Got2: <%s>", *i);

        ASSERT_STREQ(a[0], "one=2");
        ASSERT_STREQ(a[1], "twelve=12");
        ASSERT_STREQ(a[2], "twentyone=21");
        ASSERT_STREQ(a[3], "twentytwo=22");
        ASSERT_STREQ(a[4], "xxx=0x222");
        ASSERT_STREQ(a[5], "xxx_minus_three=0x222 - 3");
        ASSERT_STREQ(a[6], "yyy=2");
        ASSERT_STREQ(a[7], "zzz=replacement");
        ASSERT_STREQ(a[8], "zzzz=");
        ASSERT_STREQ(a[9], "zzzzz=");
        ASSERT_NULL(a[10]);
}

TEST(merge_env_file_invalid) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **a = NULL;

        ASSERT_OK(fmkostemp_safe(t, "w", &f));

        ASSERT_OK(write_string_stream(f,
                                      "unset one   \n"
                                      "unset one=   \n"
                                      "unset one=1   \n"
                                      "one   \n"
                                      "one =  \n"
                                      "one two =\n"
                                      "\x20two=\n"
                                      "#comment=comment\n"
                                      ";comment2=comment2\n"
                                      "#\n"
                                      "\n\n"                  /* empty line */
                                      , WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK(merge_env_file(&a, NULL, t));

        STRV_FOREACH(i, a)
                log_debug("Got: <%s>", *i);

        ASSERT_TRUE(strv_isempty(a));
}

static void check_file_pairs_one(char **l) {
        ASSERT_EQ(strv_length(l), 14U);

        STRV_FOREACH_PAIR(k, v, l) {
                if (streq(*k, "NAME"))
                        ASSERT_STREQ(*v, "Arch Linux");
                else if (streq(*k, "ID"))
                        ASSERT_STREQ(*v, "arch");
                else if (streq(*k, "PRETTY_NAME"))
                        ASSERT_STREQ(*v, "Arch Linux");
                else if (streq(*k, "ANSI_COLOR"))
                        ASSERT_STREQ(*v, "0;36");
                else if (streq(*k, "HOME_URL"))
                        ASSERT_STREQ(*v, "https://www.archlinux.org/");
                else if (streq(*k, "SUPPORT_URL"))
                        ASSERT_STREQ(*v, "https://bbs.archlinux.org/");
                else if (streq(*k, "BUG_REPORT_URL"))
                        ASSERT_STREQ(*v, "https://bugs.archlinux.org/");
                else
                        assert_not_reached();
        }
}

TEST(load_env_file_pairs) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-load_env_file_pairs-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **l = NULL;
        int fd;

        ASSERT_OK(fd = mkostemp_safe(fn));

        ASSERT_OK(write_string_file(fn,
                                    "NAME=\"Arch Linux\"\n"
                                    "ID=arch\n"
                                    "PRETTY_NAME=\"Arch Linux\"\n"
                                    "ANSI_COLOR=\"0;36\"\n"
                                    "HOME_URL=\"https://www.archlinux.org/\"\n"
                                    "SUPPORT_URL=\"https://bbs.archlinux.org/\"\n"
                                    "BUG_REPORT_URL=\"https://bugs.archlinux.org/\"\n"
                                    , WRITE_STRING_FILE_CREATE));

        ASSERT_OK(load_env_file_pairs_fd(fd, fn, &l));
        check_file_pairs_one(l);
        l = strv_free(l);

        ASSERT_NOT_NULL(f = fdopen(fd, "r"));

        ASSERT_OK(load_env_file_pairs(f, fn, &l));
        check_file_pairs_one(l);
}

DEFINE_TEST_MAIN(LOG_INFO);
