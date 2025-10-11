/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

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
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
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

        r = load_env_file(NULL, t, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

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
                log_info("Got2: <%s>", *i);
                ASSERT_STREQ(*i, a[k++]);
        }

        r = parse_env_file(
                        NULL, t,
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
                       "thirteen", &thirteen);
        assert_se(r == 0);

        log_info("one=[%s]", strna(one));
        log_info("two=[%s]", strna(two));
        log_info("three=[%s]", strna(three));
        log_info("four=[%s]", strna(four));
        log_info("five=[%s]", strna(five));
        log_info("six=[%s]", strna(six));
        log_info("seven=[%s]", strna(seven));
        log_info("eight=[%s]", strna(eight));
        log_info("export nine=[%s]", strna(nine));
        log_info("ten=[%s]", strna(nine));
        log_info("eleven=[%s]", strna(eleven));
        log_info("twelve=[%s]", strna(twelve));
        log_info("thirteen=[%s]", strna(thirteen));

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

        {
                /* prepare a temporary file to write the environment to */
                _cleanup_close_ int fd = mkostemp_safe(p);
                assert_se(fd >= 0);
        }

        r = write_env_file(AT_FDCWD, p, /* headers= */ NULL, a, /* flags= */ 0);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, &b);
        assert_se(r >= 0);
}

static void test_one_shell_var(const char *file, const char *variable, const char *value) {
        _cleanup_free_ char *cmd = NULL, *from_shell = NULL;
        _cleanup_pclose_ FILE *f = NULL;
        size_t sz;

        assert_se(cmd = strjoin(". ", file, " && /bin/echo -n \"$", variable, "\""));
        assert_se(f = popen(cmd, "re"));
        assert_se(read_full_stream(f, &from_shell, &sz) >= 0);
        assert_se(sz == strlen(value));
        ASSERT_STREQ(from_shell, value);
}

TEST(parse_multiline_env_file) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        FILE *f;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
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

        assert_se(fflush_and_check(f) >= 0);
        fclose(f);

        test_one_shell_var(t, "one", "BAR    VAR\tGAR");
        test_one_shell_var(t, "two", "bar    var\tgar");
        test_one_shell_var(t, "tri", "bar     var \tgar ");

        r = load_env_file(NULL, t, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        ASSERT_STREQ(a[0], "one=BAR    VAR\tGAR");
        ASSERT_STREQ(a[1], "two=bar    var\tgar");
        ASSERT_STREQ(a[2], "tri=bar     var \tgar ");
        ASSERT_NULL(a[3]);

        {
                _cleanup_close_ int fd = mkostemp_safe(p);
                assert_se(fd >= 0);
        }

        r = write_env_file(AT_FDCWD, p, /* headers= */ NULL, a, /* flags= */ 0);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, &b);
        assert_se(r >= 0);
}

TEST(merge_env_file) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **a = NULL;
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
        log_info("/* %s (%s) */", __func__, t);

        r = write_string_stream(f,
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
                                , WRITE_STRING_FILE_AVOID_NEWLINE);
        assert_se(r >= 0);

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

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

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_info("Got2: <%s>", *i);

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
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
        log_info("/* %s (%s) */", __func__, t);

        r = write_string_stream(f,
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
                                , WRITE_STRING_FILE_AVOID_NEWLINE);
        assert_se(r >= 0);

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(strv_isempty(a));
}

TEST(script_get_shebang_interpreter) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        char *command;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
        fputs("#! /bin/script -a -b \ngoo goo", f);
        fflush(f);

        ASSERT_OK(script_get_shebang_interpreter(t, &command));
        ASSERT_STREQ(command, "/bin/script");
        free(command);

        ASSERT_ERROR(script_get_shebang_interpreter("/bin/sh", NULL), EMEDIUMTYPE);

        if (script_get_shebang_interpreter("/usr/bin/yum", &command) >= 0) {
                assert_se(startswith(command, "/"));
                free(command);
        }
}

TEST(status_field) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        unsigned long long total = 0, buffers = 0;
        int r;

        r = get_proc_field("/proc/meminfo", "MemTotal", &p);
        if (!IN_SET(r, -ENOENT, -ENOSYS)) {
                assert_se(r == 0);
                puts(p);
                assert_se(safe_atollu(p, &total) == 0);
        }

        r = get_proc_field("/proc/meminfo", "Buffers", &s);
        if (!IN_SET(r, -ENOENT, -ENOSYS)) {
                assert_se(r == 0);
                puts(s);
                assert_se(safe_atollu(s, &buffers) == 0);
        }

        if (p)
                assert_se(buffers < total);
}

TEST(read_one_line_file) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-fileio-1lf-XXXXXX";
        int fd;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *buf, *buf2, *buf3, *buf4, *buf5;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        f = fdopen(fd, "we");
        assert_se(f);

        assert_se(read_one_line_file(fn, &buf) == 0);
        ASSERT_STREQ(buf, "");
        assert_se(read_one_line_file(fn, &buf2) == 0);
        ASSERT_STREQ(buf2, "");

        assert_se(write_string_stream(f, "x", WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);
        fflush(f);

        assert_se(read_one_line_file(fn, &buf3) == 1);
        ASSERT_STREQ(buf3, "x");

        assert_se(write_string_stream(f, "\n", WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);
        fflush(f);

        assert_se(read_one_line_file(fn, &buf4) == 2);
        ASSERT_STREQ(buf4, "x");

        assert_se(write_string_stream(f, "\n", WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);
        fflush(f);

        assert_se(read_one_line_file(fn, &buf5) == 2);
        ASSERT_STREQ(buf5, "x");
}

TEST(write_string_stream) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_stream-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        int fd;
        char buf[64];

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        f = fdopen(fd, "r");
        assert_se(f);
#ifdef __GLIBC__
        ASSERT_ERROR(write_string_stream(f, "boohoo", 0), EBADF);
#else
        /* Even the file is opened with the read-only mode, fputs() and fputc() by musl succeed but nothing
         * actually written, thus write_string_stream() also succeeds. */
        ASSERT_OK(write_string_stream(f, "boohoo", 0));
        rewind(f);
        ASSERT_NULL(fgets(buf, sizeof(buf), f));
#endif
        f = safe_fclose(f);

        f = fopen(fn, "r+");
        assert_se(f);

        assert_se(write_string_stream(f, "boohoo", 0) == 0);
        rewind(f);

        assert_se(fgets(buf, sizeof(buf), f));
        ASSERT_STREQ(buf, "boohoo\n");
        f = safe_fclose(f);

        f = fopen(fn, "w+");
        assert_se(f);

        assert_se(write_string_stream(f, "boohoo", WRITE_STRING_FILE_AVOID_NEWLINE) == 0);
        rewind(f);

        assert_se(fgets(buf, sizeof(buf), f));
        printf(">%s<", buf);
        ASSERT_STREQ(buf, "boohoo");
}

TEST(write_string_file) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_file-XXXXXX";
        char buf[64] = {};
        _cleanup_close_ int fd = -EBADF;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        assert_se(write_string_file(fn, "boohoo", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(read(fd, buf, sizeof(buf)) == 7);
        ASSERT_STREQ(buf, "boohoo\n");
}

TEST(write_string_file_no_create) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_file_no_create-XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        char buf[64] = {};

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        assert_se(write_string_file("/a/file/which/does/not/exists/i/guess", "boohoo", 0) < 0);
        assert_se(write_string_file(fn, "boohoo", 0) == 0);

        assert_se(read(fd, buf, sizeof buf) == (ssize_t) strlen("boohoo\n"));
        ASSERT_STREQ(buf, "boohoo\n");
}

TEST(write_string_file_verify) {
        _cleanup_free_ char *buf = NULL, *buf2 = NULL;
        int r;

        r = read_one_line_file("/proc/version", &buf);
        if (ERRNO_IS_NEG_PRIVILEGE(r))
                return;
        assert_se(r >= 0);
        assert_se(buf2 = strjoin(buf, "\n"));

        r = write_string_file("/proc/version", buf, 0);
        assert_se(IN_SET(r, -EACCES, -EIO));
        r = write_string_file("/proc/version", buf2, 0);
        assert_se(IN_SET(r, -EACCES, -EIO));

        assert_se(write_string_file("/proc/version", buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE) == 0);
        assert_se(write_string_file("/proc/version", buf2, WRITE_STRING_FILE_VERIFY_ON_FAILURE) == 0);

        r = write_string_file("/proc/version", buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_AVOID_NEWLINE);
        assert_se(IN_SET(r, -EACCES, -EIO));
        assert_se(write_string_file("/proc/version", buf2, WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_AVOID_NEWLINE) == 0);
}

static void check_file_pairs_one(char **l) {
        assert_se(l);
        assert_se(strv_length(l) == 14);

        STRV_FOREACH_PAIR(k, v, l) {
                assert_se(STR_IN_SET(*k, "NAME", "ID", "PRETTY_NAME", "ANSI_COLOR", "HOME_URL", "SUPPORT_URL", "BUG_REPORT_URL"));
                printf("%s=%s\n", *k, *v);
                assert_se(!streq(*k, "NAME") || streq(*v, "Arch Linux"));
                assert_se(!streq(*k, "ID") || streq(*v, "arch"));
                assert_se(!streq(*k, "PRETTY_NAME") || streq(*v, "Arch Linux"));
                assert_se(!streq(*k, "ANSI_COLOR") || streq(*v, "0;36"));
                assert_se(!streq(*k, "HOME_URL") || streq(*v, "https://www.archlinux.org/"));
                assert_se(!streq(*k, "SUPPORT_URL") || streq(*v, "https://bbs.archlinux.org/"));
                assert_se(!streq(*k, "BUG_REPORT_URL") || streq(*v, "https://bugs.archlinux.org/"));
        }
}

TEST(load_env_file_pairs) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-load_env_file_pairs-XXXXXX";
        int fd, r;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **l = NULL;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        r = write_string_file(fn,
                        "NAME=\"Arch Linux\"\n"
                        "ID=arch\n"
                        "PRETTY_NAME=\"Arch Linux\"\n"
                        "ANSI_COLOR=\"0;36\"\n"
                        "HOME_URL=\"https://www.archlinux.org/\"\n"
                        "SUPPORT_URL=\"https://bbs.archlinux.org/\"\n"
                        "BUG_REPORT_URL=\"https://bugs.archlinux.org/\"\n",
                        WRITE_STRING_FILE_CREATE);
        assert_se(r == 0);

        r = load_env_file_pairs_fd(fd, fn, &l);
        assert_se(r >= 0);
        check_file_pairs_one(l);
        l = strv_free(l);

        f = fdopen(fd, "r");
        assert_se(f);

        r = load_env_file_pairs(f, fn, &l);
        assert_se(r >= 0);
        check_file_pairs_one(l);
}

TEST(search_and_fopen) {
        static const char* const dirs[] = {
                "/tmp/foo/bar",
                "/tmp",
                NULL
        };
        char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL, *bn = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *e;
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        fd = safe_close(fd);

        ASSERT_OK(path_extract_filename(name, &bn));
        ASSERT_OK(search_and_fopen(bn, "re", NULL, (const char**) dirs, &f, &p));
        assert_se(e = path_startswith(p, "/tmp/"));
        ASSERT_STREQ(bn, e);
        f = safe_fclose(f);
        p = mfree(p);

        ASSERT_OK(search_and_fopen(bn, NULL, NULL, (const char**) dirs, NULL, &p));
        assert_se(e = path_startswith(p, "/tmp/"));
        ASSERT_STREQ(bn, e);
        p = mfree(p);

        ASSERT_OK(search_and_fopen(name, "re", NULL, (const char**) dirs, &f, &p));
        assert_se(path_equal(name, p));
        f = safe_fclose(f);
        p = mfree(p);

        ASSERT_OK(search_and_fopen(name, NULL, NULL, (const char**) dirs, NULL, &p));
        assert_se(path_equal(name, p));
        p = mfree(p);

        ASSERT_OK(search_and_fopen(bn, "re", "/", (const char**) dirs, &f, &p));
        assert_se(e = path_startswith(p, "/tmp/"));
        ASSERT_STREQ(bn, e);
        f = safe_fclose(f);
        p = mfree(p);

        ASSERT_OK(search_and_fopen(bn, NULL, "/", (const char**) dirs, NULL, &p));
        assert_se(e = path_startswith(p, "/tmp/"));
        ASSERT_STREQ(bn, e);
        p = mfree(p);

        ASSERT_ERROR(search_and_fopen("/a/file/which/does/not/exist/i/guess", "re", NULL, (const char**) dirs, &f, &p), ENOENT);
        ASSERT_ERROR(search_and_fopen("/a/file/which/does/not/exist/i/guess", NULL, NULL, (const char**) dirs, NULL, &p), ENOENT);
        ASSERT_ERROR(search_and_fopen("afilewhichdoesnotexistiguess", "re", NULL, (const char**) dirs, &f, &p), ENOENT);
        ASSERT_ERROR(search_and_fopen("afilewhichdoesnotexistiguess", NULL, NULL, (const char**) dirs, NULL, &p), ENOENT);

        r = unlink(name);
        assert_se(r == 0);

        ASSERT_ERROR(search_and_fopen(bn, "re", NULL, (const char**) dirs, &f, &p), ENOENT);
        ASSERT_ERROR(search_and_fopen(bn, NULL, NULL, (const char**) dirs, NULL, &p), ENOENT);
}

TEST(search_and_fopen_nulstr) {
        static const char dirs[] =
                "/tmp/foo/bar\0"
                "/tmp\0";

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL, *bn = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *e;
        int r;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        fd = safe_close(fd);

        ASSERT_OK(path_extract_filename(name, &bn));
        ASSERT_OK(search_and_fopen_nulstr(bn, "re", NULL, dirs, &f, &p));
        assert_se(e = path_startswith(p, "/tmp/"));
        ASSERT_STREQ(bn, e);
        f = safe_fclose(f);
        p = mfree(p);

        ASSERT_OK(search_and_fopen_nulstr(name, "re", NULL, dirs, &f, &p));
        assert_se(path_equal(name, p));
        f = safe_fclose(f);
        p = mfree(p);

        ASSERT_ERROR(search_and_fopen_nulstr("/a/file/which/does/not/exist/i/guess", "re", NULL, dirs, &f, &p), ENOENT);
        ASSERT_ERROR(search_and_fopen_nulstr("afilewhichdoesnotexistiguess", "re", NULL, dirs, &f, &p), ENOENT);

        r = unlink(name);
        assert_se(r == 0);

        ASSERT_ERROR(search_and_fopen_nulstr(bn, "re", NULL, dirs, &f, &p), ENOENT);
}

TEST(writing_tmpfile) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-systemd_writing_tmpfile.XXXXXX";
        _cleanup_free_ char *contents = NULL;
        size_t size;
        _cleanup_close_ int fd = -EBADF;
        int r;

        struct iovec iov[] = {
                IOVEC_MAKE_STRING("abc\n"),
                IOVEC_MAKE_STRING(ALPHANUMERICAL "\n"),
                IOVEC_MAKE_STRING(""),
        };

        fd = mkostemp_safe(name);
        printf("tmpfile: %s", name);

        r = writev(fd, iov, 3);
        assert_se(r >= 0);

        r = read_full_file(name, &contents, &size);
        assert_se(r == 0);
        printf("contents: %s", contents);
        ASSERT_STREQ(contents, "abc\n" ALPHANUMERICAL "\n");
}

TEST(tempfn) {
        char *ret = NULL, *p;

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", NULL, &ret) >= 0);
        ASSERT_STREQ(ret, "/foo/bar/.#waldoXXXXXX");
        free(ret);

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", "[miau]", &ret) >= 0);
        ASSERT_STREQ(ret, "/foo/bar/.#[miau]waldoXXXXXX");
        free(ret);

        assert_se(tempfn_random("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/.#waldo"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random("/foo/bar/waldo", "[wuff]", &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/.#[wuff]waldo"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random_child("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/waldo/.#"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);

        assert_se(tempfn_random_child("/foo/bar/waldo", "[kikiriki]", &ret) >= 0);
        assert_se(p = startswith(ret, "/foo/bar/waldo/.#[kikiriki]"));
        assert_se(strlen(p) == 16);
        assert_se(in_charset(p, "0123456789abcdef"));
        free(ret);
}

static const char chars[] =
        "Aąę„”\n루\377";

DISABLE_WARNING_TYPE_LIMITS;

TEST(fgetc) {
        _cleanup_fclose_ FILE *f = NULL;
        char c;

        assert_se(f = fmemopen_unlocked((void*) chars, sizeof(chars), "r"));

        for (size_t i = 0; i < sizeof(chars); i++) {
                assert_se(safe_fgetc(f, &c) == 1);
                assert_se(c == chars[i]);

                if (ungetc(c, f) == EOF) {
                        /* EOF is -1, and hence we can't push value 255 in this way – if char is signed */
                        assert_se(c == (char) EOF);
                        assert_se(CHAR_MIN == -128); /* verify that char is signed on this platform */
                } else {
                        assert_se(safe_fgetc(f, &c) == 1);
                        assert_se(c == chars[i]);
                }

                /* But it works when we push it properly cast */
                assert_se(ungetc((unsigned char) c, f) != EOF);
                assert_se(safe_fgetc(f, &c) == 1);
                assert_se(c == chars[i]);
        }

        assert_se(safe_fgetc(f, &c) == 0);
}

REENABLE_WARNING;

static const char buffer[] =
        "Some test data\n"
        "루Non-ascii chars: ąę„”\n"
        "terminators\r\n"
        "and even more\n\r"
        "now the same with a NUL\n\0"
        "and more\r\0"
        "and even more\r\n\0"
        "and yet even more\n\r\0"
        "With newlines, and a NUL byte\0"
        "\n"
        "an empty line\n"
        "an ignored line\n"
        "and a very long line that is supposed to be truncated, because it is so long\n";

static void test_read_line_one_file(FILE *f) {
        _cleanup_free_ char *line = NULL;

        assert_se(read_line(f, SIZE_MAX, &line) == 15 && streq(line, "Some test data"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) > 0 && streq(line, "루Non-ascii chars: ąę„”"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 13 && streq(line, "terminators"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 15 && streq(line, "and even more"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 25 && streq(line, "now the same with a NUL"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 10 && streq(line, "and more"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 16 && streq(line, "and even more"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, &line) == 20 && streq(line, "and yet even more"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 30 && streq(line, "With newlines, and a NUL byte"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 1 && streq(line, ""));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 14 && streq(line, "an empty line"));
        line = mfree(line);

        assert_se(read_line(f, SIZE_MAX, NULL) == 16);

        assert_se(read_line(f, 16, &line) == -ENOBUFS);
        line = mfree(line);

        /* read_line() stopped when it hit the limit, that means when we continue reading we'll read at the first
         * character after the previous limit. Let's make use of that to continue our test. */
        assert_se(read_line(f, 1024, &line) == 62 && streq(line, "line that is supposed to be truncated, because it is so long"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 0 && streq(line, ""));
}

TEST(read_line1) {
        _cleanup_fclose_ FILE *f = NULL;

        assert_se(f = fmemopen_unlocked((void*) buffer, sizeof(buffer), "r"));
        test_read_line_one_file(f);
}

TEST(read_line2) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-fileio.XXXXXX";
        int fd;
        _cleanup_fclose_ FILE *f = NULL;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        assert_se((size_t) write(fd, buffer, sizeof(buffer)) == sizeof(buffer));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(f = fdopen(fd, "r"));

        test_read_line_one_file(f);
}

TEST(read_line3) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        int r;

        f = fopen("/proc/uptime", "re");
        if (!f && IN_SET(errno, ENOENT, EPERM))
                return;
        assert_se(f);

        r = read_line(f, LINE_MAX, &line);
        assert_se(r >= 0);
        if (r == 0)
                assert_se(line && isempty(line));
        else
                assert_se((size_t) r == strlen(line) + 1);
        assert_se(read_line(f, LINE_MAX, NULL) == 0);
}

TEST(read_line4) {
        static const struct {
                size_t length;
                const char *string;
        } eof_endings[] = {
                /* Each of these will be followed by EOF and should generate the one same single string */
                { 3, "foo" },
                { 4, "foo\n" },
                { 4, "foo\r" },
                { 4, "foo\0" },
                { 5, "foo\n\0" },
                { 5, "foo\r\0" },
                { 5, "foo\r\n" },
                { 5, "foo\n\r" },
                { 6, "foo\r\n\0" },
                { 6, "foo\n\r\0" },
        };

        int r;

        FOREACH_ELEMENT(ending, eof_endings) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *s = NULL;

                assert_se(f = fmemopen_unlocked((void*) ending->string, ending->length, "r"));

                r = read_line(f, SIZE_MAX, &s);
                assert_se((size_t) r == ending->length);
                ASSERT_STREQ(s, "foo");

                assert_se(read_line(f, SIZE_MAX, NULL) == 0); /* Ensure we hit EOF */
        }
}

TEST(read_nul_string) {
        static const char test[] = "string nr. 1\0"
                "string nr. 2\n\0"
                "\377empty string follows\0"
                "\0"
                "final string\n is empty\0"
                "\0";

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *s = NULL;

        assert_se(f = fmemopen_unlocked((void*) test, sizeof(test)-1, "r"));

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 13 && streq_ptr(s, "string nr. 1"));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 14 && streq_ptr(s, "string nr. 2\n"));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 22 && streq_ptr(s, "\377empty string follows"));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 1 && streq_ptr(s, ""));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 23 && streq_ptr(s, "final string\n is empty"));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 1 && streq_ptr(s, ""));
        s = mfree(s);

        assert_se(read_nul_string(f, LONG_LINE_MAX, &s) == 0 && streq_ptr(s, ""));
}

TEST(read_full_file_socket) {
        _cleanup_(rm_rf_physical_and_freep) char *z = NULL;
        _cleanup_close_ int listener = -EBADF;
        _cleanup_free_ char *data = NULL, *clientname = NULL;
        union sockaddr_union sa;
        const char *j, *jj;
        size_t size;
        pid_t pid;
        int r;

        listener = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        assert_se(listener >= 0);

        assert_se(mkdtemp_malloc(NULL, &z) >= 0);
        j = strjoina(z, "/socket");

        assert_se(sockaddr_un_set_path(&sa.un, j) >= 0);

        assert_se(bind(listener, &sa.sa, sockaddr_un_len(&sa.un)) >= 0);
        assert_se(listen(listener, 1) >= 0);

        /* Make sure the socket doesn't fit into a struct sockaddr_un, but we can still access it */
        jj = strjoina(z, "/a_very_long_patha_very_long_patha_very_long_patha_very_long_patha_very_long_patha_very_long_patha_very_long_patha_very_long_path");
        assert_se(strlen(jj) > sizeof_field(struct sockaddr_un, sun_path));
        assert_se(rename(j, jj) >= 0);

        /* Bind the *client* socket to some randomized name, to verify that this works correctly. */
        assert_se(asprintf(&clientname, "@%" PRIx64 "/test-bindname", random_u64()) >= 0);

        r = safe_fork("(server)", FORK_DEATHSIG_SIGTERM|FORK_LOG, &pid);
        assert_se(r >= 0);
        if (r == 0) {
                union sockaddr_union peer = {};
                socklen_t peerlen = sizeof(peer);
                _cleanup_close_ int rfd = -EBADF;
                /* child */

                rfd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
                assert_se(rfd >= 0);

                assert_se(getpeername(rfd, &peer.sa, &peerlen) >= 0);

                assert_se(peer.un.sun_family == AF_UNIX);
                assert_se(peerlen > offsetof(struct sockaddr_un, sun_path));
                assert_se(peer.un.sun_path[0] == 0);
                ASSERT_STREQ(peer.un.sun_path + 1, clientname + 1);

#define TEST_STR "This is a test\nreally."

                assert_se(write(rfd, TEST_STR, strlen(TEST_STR)) == strlen(TEST_STR));
                _exit(EXIT_SUCCESS);
        }

        assert_se(read_full_file_full(AT_FDCWD, jj, UINT64_MAX, SIZE_MAX, 0, NULL, &data, &size) == -ENXIO);
        assert_se(read_full_file_full(AT_FDCWD, jj, UINT64_MAX, SIZE_MAX, READ_FULL_FILE_CONNECT_SOCKET, clientname, &data, &size) >= 0);
        assert_se(size == strlen(TEST_STR));
        ASSERT_STREQ(data, TEST_STR);

        assert_se(wait_for_terminate_and_check("(server)", pid, WAIT_LOG) >= 0);
#undef TEST_STR
}

TEST(read_full_file_offset_size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_and_freep) char *fn = NULL;
        _cleanup_free_ char *rbuf = NULL;
        size_t rbuf_size;
        uint8_t buf[4711];

        random_bytes(buf, sizeof(buf));

        assert_se(tempfn_random_child(NULL, NULL, &fn) >= 0);
        assert_se(f = fopen(fn, "we"));
        assert_se(fwrite(buf, 1, sizeof(buf), f) == sizeof(buf));
        assert_se(fflush_and_check(f) >= 0);

        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, SIZE_MAX, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == sizeof(buf));
        assert_se(memcmp(buf, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, 128, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == 128);
        assert_se(memcmp(buf, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, 128, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) == -E2BIG);
        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, sizeof(buf)-1, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) == -E2BIG);
        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, sizeof(buf), READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == sizeof(buf));
        assert_se(memcmp(buf, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, 47, 128, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) == -E2BIG);
        assert_se(read_full_file_full(AT_FDCWD, fn, 47, sizeof(buf)-47-1, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) == -E2BIG);
        assert_se(read_full_file_full(AT_FDCWD, fn, 47, sizeof(buf)-47, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == sizeof(buf)-47);
        assert_se(memcmp(buf+47, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, UINT64_MAX, sizeof(buf)+1, READ_FULL_FILE_FAIL_WHEN_LARGER, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == sizeof(buf));
        assert_se(memcmp(buf, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, 1234, SIZE_MAX, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == sizeof(buf) - 1234);
        assert_se(memcmp(buf + 1234, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, 2345, 777, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == 777);
        assert_se(memcmp(buf + 2345, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, 4700, 20, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == 11);
        assert_se(memcmp(buf + 4700, rbuf, rbuf_size) == 0);
        rbuf = mfree(rbuf);

        assert_se(read_full_file_full(AT_FDCWD, fn, 10000, 99, 0, NULL, &rbuf, &rbuf_size) >= 0);
        assert_se(rbuf_size == 0);
        rbuf = mfree(rbuf);
}

static void test_read_virtual_file_one(size_t max_size) {
        int r;

        log_info("/* %s (max_size=%zu) */", __func__, max_size);

        FOREACH_STRING(filename,
                       "/proc/1/cmdline",
                       "/etc/nsswitch.conf",
                       "/sys/kernel/uevent_seqnum",
                       "/proc/kcore",
                       "/proc/kallsyms",
                       "/proc/self/exe",
                       "/proc/self/pagemap") {

                _cleanup_free_ char *buf = NULL;
                size_t size = 0;

                r = read_virtual_file(filename, max_size, &buf, &size);
                if (r < 0) {
                        log_info_errno(r, "read_virtual_file(\"%s\", %zu): %m", filename, max_size);
                        assert_se(ERRNO_IS_PRIVILEGE(r) || /* /proc/kcore is not accessible to unpriv */
                                  IN_SET(r,
                                         -ENOENT,  /* Some of the files might be absent */
                                         -EINVAL,  /* too small reads from /proc/self/pagemap trigger EINVAL */
                                         -EFBIG,   /* /proc/kcore and /proc/self/pagemap should be too large */
                                         -EBADF)); /* /proc/kcore is masked when we are running in docker. */
                } else
                        log_info("read_virtual_file(\"%s\", %zu): %s (%zu bytes)", filename, max_size, r ? "non-truncated" : "truncated", size);
        }
}

TEST(read_virtual_file) {
        test_read_virtual_file_one(0);
        test_read_virtual_file_one(1);
        test_read_virtual_file_one(2);
        test_read_virtual_file_one(20);
        test_read_virtual_file_one(4096);
        test_read_virtual_file_one(4097);
        test_read_virtual_file_one(SIZE_MAX);
}

TEST(fdopen_independent) {
#define TEST_TEXT "this is some random test text we are going to write to a memfd"
        _cleanup_close_ int fd = -EBADF;
        _cleanup_fclose_ FILE *f = NULL;
        char buf[STRLEN(TEST_TEXT) + 1];

        fd = memfd_new("fdopen_independent");
        if (fd < 0) {
                assert_se(ERRNO_IS_NOT_SUPPORTED(fd));
                return;
        }

        assert_se(write(fd, TEST_TEXT, strlen(TEST_TEXT)) == strlen(TEST_TEXT));
        /* we'll leave the read offset at the end of the memfd, the fdopen_independent() descriptors should
         * start at the beginning anyway */

        assert_se(fdopen_independent(fd, "re", &f) >= 0);
        zero(buf);
        assert_se(fread(buf, 1, sizeof(buf), f) == strlen(TEST_TEXT));
        ASSERT_STREQ(buf, TEST_TEXT);
        assert_se((fcntl(fileno(f), F_GETFL) & O_ACCMODE_STRICT) == O_RDONLY);
        assert_se(FLAGS_SET(fcntl(fileno(f), F_GETFD), FD_CLOEXEC));
        f = safe_fclose(f);

        assert_se(fdopen_independent(fd, "r", &f) >= 0);
        zero(buf);
        assert_se(fread(buf, 1, sizeof(buf), f) == strlen(TEST_TEXT));
        ASSERT_STREQ(buf, TEST_TEXT);
        assert_se((fcntl(fileno(f), F_GETFL) & O_ACCMODE_STRICT) == O_RDONLY);
        assert_se(!FLAGS_SET(fcntl(fileno(f), F_GETFD), FD_CLOEXEC));
        f = safe_fclose(f);

        assert_se(fdopen_independent(fd, "r+e", &f) >= 0);
        zero(buf);
        assert_se(fread(buf, 1, sizeof(buf), f) == strlen(TEST_TEXT));
        ASSERT_STREQ(buf, TEST_TEXT);
        assert_se((fcntl(fileno(f), F_GETFL) & O_ACCMODE_STRICT) == O_RDWR);
        assert_se(FLAGS_SET(fcntl(fileno(f), F_GETFD), FD_CLOEXEC));
        f = safe_fclose(f);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
