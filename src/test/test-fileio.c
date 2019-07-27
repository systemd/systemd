/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "ctype.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "util.h"

static void test_parse_env_file(void) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        FILE *f;
        _cleanup_free_ char *one = NULL, *two = NULL, *three = NULL, *four = NULL, *five = NULL,
                        *six = NULL, *seven = NULL, *eight = NULL, *nine = NULL, *ten = NULL,
                        *eleven = NULL, *twelve = NULL, *thirteen = NULL;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        char **i;
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

        assert_se(streq_ptr(a[0], "one=BAR"));
        assert_se(streq_ptr(a[1], "two=bar"));
        assert_se(streq_ptr(a[2], "three=333\nxxxx"));
        assert_se(streq_ptr(a[3], "four=44\\\"44"));
        assert_se(streq_ptr(a[4], "five=55\"55FIVEcinco"));
        assert_se(streq_ptr(a[5], "six=seis sechs sis"));
        assert_se(streq_ptr(a[6], "seven=sevenval#nocomment"));
        assert_se(streq_ptr(a[7], "eight=eightval #nocomment"));
        assert_se(streq_ptr(a[8], "export nine=nineval"));
        assert_se(streq_ptr(a[9], "ten="));
        assert_se(streq_ptr(a[10], "eleven=value"));
        assert_se(streq_ptr(a[11], "twelve=\\value"));
        assert_se(streq_ptr(a[12], "thirteen=\\value"));
        assert_se(a[13] == NULL);

        strv_env_clean(a);

        k = 0;
        STRV_FOREACH(i, b) {
                log_info("Got2: <%s>", *i);
                assert_se(streq(*i, a[k++]));
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

        assert_se(r >= 0);

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

        assert_se(streq(one, "BAR"));
        assert_se(streq(two, "bar"));
        assert_se(streq(three, "333\nxxxx"));
        assert_se(streq(four, "44\\\"44"));
        assert_se(streq(five, "55\"55FIVEcinco"));
        assert_se(streq(six, "seis sechs sis"));
        assert_se(streq(seven, "sevenval#nocomment"));
        assert_se(streq(eight, "eightval #nocomment"));
        assert_se(streq(nine, "nineval"));
        assert_se(ten == NULL);
        assert_se(streq(eleven, "value"));
        assert_se(streq(twelve, "\\value"));
        assert_se(streq(thirteen, "\\value"));

        {
                /* prepare a temporary file to write the environment to */
                _cleanup_close_ int fd = mkostemp_safe(p);
                assert_se(fd >= 0);
        }

        r = write_env_file(p, a);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, &b);
        assert_se(r >= 0);
}

static void test_parse_multiline_env_file(void) {
        _cleanup_(unlink_tempfilep) char
                t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        FILE *f;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        char **i;
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
        fputs("one=BAR\\\n"
              "    VAR\\\n"
              "\tGAR\n"
              "#comment\n"
              "two=\"bar\\\n"
              "    var\\\n"
              "\tgar\"\n"
              "#comment\n"
              "tri=\"bar \\\n"
              "    var \\\n"
              "\tgar \"\n", f);

        fflush(f);
        fclose(f);

        r = load_env_file(NULL, t, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(streq_ptr(a[0], "one=BAR    VAR\tGAR"));
        assert_se(streq_ptr(a[1], "two=bar    var\tgar"));
        assert_se(streq_ptr(a[2], "tri=bar     var \tgar "));
        assert_se(a[3] == NULL);

        {
                _cleanup_close_ int fd = mkostemp_safe(p);
                assert_se(fd >= 0);
        }

        r = write_env_file(p, a);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, &b);
        assert_se(r >= 0);
}

static void test_merge_env_file(void) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **a = NULL;
        char **i;
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
        assert(r >= 0);

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(streq(a[0], "one=2"));
        assert_se(streq(a[1], "twelve=12"));
        assert_se(streq(a[2], "twentyone=21"));
        assert_se(streq(a[3], "twentytwo=22"));
        assert_se(streq(a[4], "xxx=0x222"));
        assert_se(streq(a[5], "xxx_minus_three= - 3"));
        assert_se(streq(a[6], "yyy=2"));
        assert_se(streq(a[7], "zzz=replacement"));
        assert_se(streq(a[8], "zzzz="));
        assert_se(streq(a[9], "zzzzz="));
        assert_se(a[10] == NULL);

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);
        strv_sort(a);

        STRV_FOREACH(i, a)
                log_info("Got2: <%s>", *i);

        assert_se(streq(a[0], "one=2"));
        assert_se(streq(a[1], "twelve=12"));
        assert_se(streq(a[2], "twentyone=21"));
        assert_se(streq(a[3], "twentytwo=22"));
        assert_se(streq(a[4], "xxx=0x222"));
        assert_se(streq(a[5], "xxx_minus_three=0x222 - 3"));
        assert_se(streq(a[6], "yyy=2"));
        assert_se(streq(a[7], "zzz=replacement"));
        assert_se(streq(a[8], "zzzz="));
        assert_se(streq(a[9], "zzzzz="));
        assert_se(a[10] == NULL);
}

static void test_merge_env_file_invalid(void) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **a = NULL;
        char **i;
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
        assert(r >= 0);

        r = merge_env_file(&a, NULL, t);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(strv_isempty(a));
}

static void test_executable_is_script(void) {
        _cleanup_(unlink_tempfilep) char t[] = "/tmp/test-fileio-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        char *command;
        int r;

        assert_se(fmkostemp_safe(t, "w", &f) == 0);
        fputs("#! /bin/script -a -b \ngoo goo", f);
        fflush(f);

        r = executable_is_script(t, &command);
        assert_se(r > 0);
        assert_se(streq(command, "/bin/script"));
        free(command);

        r = executable_is_script("/bin/sh", &command);
        assert_se(r == 0);

        r = executable_is_script("/usr/bin/yum", &command);
        assert_se(r > 0 || r == -ENOENT);
        if (r > 0) {
                assert_se(startswith(command, "/"));
                free(command);
        }
}

static void test_status_field(void) {
        _cleanup_free_ char *t = NULL, *p = NULL, *s = NULL, *z = NULL;
        unsigned long long total = 0, buffers = 0;
        int r;

        assert_se(get_proc_field("/proc/self/status", "Threads", WHITESPACE, &t) == 0);
        puts(t);
        assert_se(streq(t, "1"));

        r = get_proc_field("/proc/meminfo", "MemTotal", WHITESPACE, &p);
        if (r != -ENOENT) {
                assert_se(r == 0);
                puts(p);
                assert_se(safe_atollu(p, &total) == 0);
        }

        r = get_proc_field("/proc/meminfo", "Buffers", WHITESPACE, &s);
        if (r != -ENOENT) {
                assert_se(r == 0);
                puts(s);
                assert_se(safe_atollu(s, &buffers) == 0);
        }

        if (p)
                assert_se(buffers < total);

        /* Seccomp should be a good test for field full of zeros. */
        r = get_proc_field("/proc/meminfo", "Seccomp", WHITESPACE, &z);
        if (r != -ENOENT) {
                assert_se(r == 0);
                puts(z);
                assert_se(safe_atollu(z, &buffers) == 0);
        }
}

static void test_capeff(void) {
        int pid, p;

        for (pid = 0; pid < 2; pid++) {
                _cleanup_free_ char *capeff = NULL;
                int r;

                r = get_process_capeff(0, &capeff);
                log_info("capeff: '%s' (r=%d)", capeff, r);

                if (IN_SET(r, -ENOENT, -EPERM))
                        return;

                assert_se(r == 0);
                assert_se(*capeff);
                p = capeff[strspn(capeff, HEXDIGITS)];
                assert_se(!p || isspace(p));
        }
}

static void test_write_string_stream(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_stream-XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        int fd;
        char buf[64];

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        f = fdopen(fd, "r");
        assert_se(f);
        assert_se(write_string_stream(f, "boohoo", 0) < 0);
        f = safe_fclose(f);

        f = fopen(fn, "r+");
        assert_se(f);

        assert_se(write_string_stream(f, "boohoo", 0) == 0);
        rewind(f);

        assert_se(fgets(buf, sizeof(buf), f));
        assert_se(streq(buf, "boohoo\n"));
        f = safe_fclose(f);

        f = fopen(fn, "w+");
        assert_se(f);

        assert_se(write_string_stream(f, "boohoo", WRITE_STRING_FILE_AVOID_NEWLINE) == 0);
        rewind(f);

        assert_se(fgets(buf, sizeof(buf), f));
        printf(">%s<", buf);
        assert_se(streq(buf, "boohoo"));
}

static void test_write_string_file(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_file-XXXXXX";
        char buf[64] = {};
        _cleanup_close_ int fd;

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        assert_se(write_string_file(fn, "boohoo", WRITE_STRING_FILE_CREATE) == 0);

        assert_se(read(fd, buf, sizeof(buf)) == 7);
        assert_se(streq(buf, "boohoo\n"));
}

static void test_write_string_file_no_create(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-write_string_file_no_create-XXXXXX";
        _cleanup_close_ int fd;
        char buf[64] = {};

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        assert_se(write_string_file("/a/file/which/does/not/exists/i/guess", "boohoo", 0) < 0);
        assert_se(write_string_file(fn, "boohoo", 0) == 0);

        assert_se(read(fd, buf, sizeof buf) == (ssize_t) strlen("boohoo\n"));
        assert_se(streq(buf, "boohoo\n"));
}

static void test_write_string_file_verify(void) {
        _cleanup_free_ char *buf = NULL, *buf2 = NULL;
        int r;

        assert_se(read_one_line_file("/proc/cmdline", &buf) >= 0);
        assert_se(buf2 = strjoin(buf, "\n"));

        r = write_string_file("/proc/cmdline", buf, 0);
        assert_se(IN_SET(r, -EACCES, -EIO));
        r = write_string_file("/proc/cmdline", buf2, 0);
        assert_se(IN_SET(r, -EACCES, -EIO));

        assert_se(write_string_file("/proc/cmdline", buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE) == 0);
        assert_se(write_string_file("/proc/cmdline", buf2, WRITE_STRING_FILE_VERIFY_ON_FAILURE) == 0);

        r = write_string_file("/proc/cmdline", buf, WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_AVOID_NEWLINE);
        assert_se(IN_SET(r, -EACCES, -EIO));
        assert_se(write_string_file("/proc/cmdline", buf2, WRITE_STRING_FILE_VERIFY_ON_FAILURE|WRITE_STRING_FILE_AVOID_NEWLINE) == 0);
}

static void test_load_env_file_pairs(void) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-load_env_file_pairs-XXXXXX";
        int fd, r;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **l = NULL;
        char **k, **v;

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

        f = fdopen(fd, "r");
        assert_se(f);

        r = load_env_file_pairs(f, fn, &l);
        assert_se(r >= 0);

        assert_se(strv_length(l) == 14);
        STRV_FOREACH_PAIR(k, v, l) {
                assert_se(STR_IN_SET(*k, "NAME", "ID", "PRETTY_NAME", "ANSI_COLOR", "HOME_URL", "SUPPORT_URL", "BUG_REPORT_URL"));
                printf("%s=%s\n", *k, *v);
                if (streq(*k, "NAME")) assert_se(streq(*v, "Arch Linux"));
                if (streq(*k, "ID")) assert_se(streq(*v, "arch"));
                if (streq(*k, "PRETTY_NAME")) assert_se(streq(*v, "Arch Linux"));
                if (streq(*k, "ANSI_COLOR")) assert_se(streq(*v, "0;36"));
                if (streq(*k, "HOME_URL")) assert_se(streq(*v, "https://www.archlinux.org/"));
                if (streq(*k, "SUPPORT_URL")) assert_se(streq(*v, "https://bbs.archlinux.org/"));
                if (streq(*k, "BUG_REPORT_URL")) assert_se(streq(*v, "https://bugs.archlinux.org/"));
        }
}

static void test_search_and_fopen(void) {
        const char *dirs[] = {"/tmp/foo/bar", "/tmp", NULL};

        char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        int fd, r;
        FILE *f;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        close(fd);

        r = search_and_fopen(basename(name), "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen(name, "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen(basename(name), "r", "/", dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen("/a/file/which/does/not/exist/i/guess", "r", NULL, dirs, &f);
        assert_se(r < 0);
        r = search_and_fopen("afilewhichdoesnotexistiguess", "r", NULL, dirs, &f);
        assert_se(r < 0);

        r = unlink(name);
        assert_se(r == 0);

        r = search_and_fopen(basename(name), "r", NULL, dirs, &f);
        assert_se(r < 0);
}

static void test_search_and_fopen_nulstr(void) {
        const char dirs[] = "/tmp/foo/bar\0/tmp\0";

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-search_and_fopen.XXXXXX";
        int fd, r;
        FILE *f;

        fd = mkostemp_safe(name);
        assert_se(fd >= 0);
        close(fd);

        r = search_and_fopen_nulstr(basename(name), "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen_nulstr(name, "r", NULL, dirs, &f);
        assert_se(r >= 0);
        fclose(f);

        r = search_and_fopen_nulstr("/a/file/which/does/not/exist/i/guess", "r", NULL, dirs, &f);
        assert_se(r < 0);
        r = search_and_fopen_nulstr("afilewhichdoesnotexistiguess", "r", NULL, dirs, &f);
        assert_se(r < 0);

        r = unlink(name);
        assert_se(r == 0);

        r = search_and_fopen_nulstr(basename(name), "r", NULL, dirs, &f);
        assert_se(r < 0);
}

static void test_writing_tmpfile(void) {
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-systemd_writing_tmpfile.XXXXXX";
        _cleanup_free_ char *contents = NULL;
        size_t size;
        _cleanup_close_ int fd = -1;
        struct iovec iov[3];
        int r;

        iov[0] = IOVEC_MAKE_STRING("abc\n");
        iov[1] = IOVEC_MAKE_STRING(ALPHANUMERICAL "\n");
        iov[2] = IOVEC_MAKE_STRING("");

        fd = mkostemp_safe(name);
        printf("tmpfile: %s", name);

        r = writev(fd, iov, 3);
        assert_se(r >= 0);

        r = read_full_file(name, &contents, &size);
        assert_se(r == 0);
        printf("contents: %s", contents);
        assert_se(streq(contents, "abc\n" ALPHANUMERICAL "\n"));
}

static void test_tempfn(void) {
        char *ret = NULL, *p;

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", NULL, &ret) >= 0);
        assert_se(streq_ptr(ret, "/foo/bar/.#waldoXXXXXX"));
        free(ret);

        assert_se(tempfn_xxxxxx("/foo/bar/waldo", "[miau]", &ret) >= 0);
        assert_se(streq_ptr(ret, "/foo/bar/.#[miau]waldoXXXXXX"));
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"

static void test_fgetc(void) {
        _cleanup_fclose_ FILE *f = NULL;
        char c;

        f = fmemopen_unlocked((void*) chars, sizeof(chars), "re");
        assert_se(f);

        for (unsigned i = 0; i < sizeof(chars); i++) {
                assert_se(safe_fgetc(f, &c) == 1);
                assert_se(c == chars[i]);

                /* EOF is -1, and hence we can't push value 255 in this way if char is signed */
                assert_se(ungetc(c, f) != EOF || c == EOF);
                assert_se(c == EOF || safe_fgetc(f, &c) == 1);
                assert_se(c == chars[i]);

                /* But it works when we push it properly cast */
                assert_se(ungetc((unsigned char) c, f) != EOF);
                assert_se(safe_fgetc(f, &c) == 1);
                assert_se(c == chars[i]);
        }

        assert_se(safe_fgetc(f, &c) == 0);
}

#pragma GCC diagnostic pop

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

        assert_se(read_line(f, (size_t) -1, &line) == 15 && streq(line, "Some test data"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) > 0 && streq(line, "루Non-ascii chars: ąę„”"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 13 && streq(line, "terminators"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 15 && streq(line, "and even more"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 25 && streq(line, "now the same with a NUL"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 10 && streq(line, "and more"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 16 && streq(line, "and even more"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, &line) == 20 && streq(line, "and yet even more"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 30 && streq(line, "With newlines, and a NUL byte"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 1 && streq(line, ""));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 14 && streq(line, "an empty line"));
        line = mfree(line);

        assert_se(read_line(f, (size_t) -1, NULL) == 16);

        assert_se(read_line(f, 16, &line) == -ENOBUFS);
        line = mfree(line);

        /* read_line() stopped when it hit the limit, that means when we continue reading we'll read at the first
         * character after the previous limit. Let's make use of that to continue our test. */
        assert_se(read_line(f, 1024, &line) == 62 && streq(line, "line that is supposed to be truncated, because it is so long"));
        line = mfree(line);

        assert_se(read_line(f, 1024, &line) == 0 && streq(line, ""));
}

static void test_read_line(void) {
        _cleanup_fclose_ FILE *f = NULL;

        f = fmemopen_unlocked((void*) buffer, sizeof(buffer), "re");
        assert_se(f);

        test_read_line_one_file(f);
}

static void test_read_line2(void) {
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

static void test_read_line3(void) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        int r;

        f = fopen("/proc/cmdline", "re");
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

static void test_read_line4(void) {
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

        size_t i;
        int r;

        for (i = 0; i < ELEMENTSOF(eof_endings); i++) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *s = NULL;

                assert_se(f = fmemopen_unlocked((void*) eof_endings[i].string, eof_endings[i].length, "r"));

                r = read_line(f, (size_t) -1, &s);
                assert_se((size_t) r == eof_endings[i].length);
                assert_se(streq_ptr(s, "foo"));

                assert_se(read_line(f, (size_t) -1, NULL) == 0); /* Ensure we hit EOF */
        }
}

static void test_read_nul_string(void) {
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

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_parse_env_file();
        test_parse_multiline_env_file();
        test_merge_env_file();
        test_merge_env_file_invalid();
        test_executable_is_script();
        test_status_field();
        test_capeff();
        test_write_string_stream();
        test_write_string_file();
        test_write_string_file_no_create();
        test_write_string_file_verify();
        test_load_env_file_pairs();
        test_search_and_fopen();
        test_search_and_fopen_nulstr();
        test_writing_tmpfile();
        test_tempfn();
        test_fgetc();
        test_read_line();
        test_read_line2();
        test_read_line3();
        test_read_line4();
        test_read_nul_string();

        return 0;
}
