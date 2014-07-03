/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"
#include "fileio.h"
#include "strv.h"
#include "env-util.h"
#include "def.h"
#include "ctype.h"

static void test_parse_env_file(void) {
        char    t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        int fd, r;
        FILE *f;
        _cleanup_free_ char *one = NULL, *two = NULL, *three = NULL, *four = NULL, *five = NULL,
                        *six = NULL, *seven = NULL, *eight = NULL, *nine = NULL, *ten = NULL;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        char **i;
        unsigned k;

        fd = mkostemp_safe(p, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        fd = mkostemp_safe(t, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        f = fdopen(fd, "w");
        assert_se(f);

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
              "five = \'55\\\'55\' \"FIVE\" cinco   \n"
              "six = seis sechs\\\n"
              " sis\n"
              "seven=\"sevenval\" #nocomment\n"
              "eight=eightval #nocomment\n"
              "export nine=nineval\n"
              "ten=", f);

        fflush(f);
        fclose(f);

        r = load_env_file(NULL, t, NULL, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(streq_ptr(a[0], "one=BAR"));
        assert_se(streq_ptr(a[1], "two=bar"));
        assert_se(streq_ptr(a[2], "three=333\nxxxx"));
        assert_se(streq_ptr(a[3], "four=44\"44"));
        assert_se(streq_ptr(a[4], "five=55\'55FIVEcinco"));
        assert_se(streq_ptr(a[5], "six=seis sechs sis"));
        assert_se(streq_ptr(a[6], "seven=sevenval#nocomment"));
        assert_se(streq_ptr(a[7], "eight=eightval #nocomment"));
        assert_se(streq_ptr(a[8], "export nine=nineval"));
        assert_se(streq_ptr(a[9], "ten="));
        assert_se(a[10] == NULL);

        strv_env_clean_log(a, "test");

        k = 0;
        STRV_FOREACH(i, b) {
                log_info("Got2: <%s>", *i);
                assert_se(streq(*i, a[k++]));
        }

        r = parse_env_file(
                        t, NULL,
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
                       NULL);

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

        assert_se(streq(one, "BAR"));
        assert_se(streq(two, "bar"));
        assert_se(streq(three, "333\nxxxx"));
        assert_se(streq(four, "44\"44"));
        assert_se(streq(five, "55\'55FIVEcinco"));
        assert_se(streq(six, "seis sechs sis"));
        assert_se(streq(seven, "sevenval#nocomment"));
        assert_se(streq(eight, "eightval #nocomment"));
        assert_se(streq(nine, "nineval"));
        assert_se(ten == NULL);

        r = write_env_file(p, a);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, NULL, &b);
        assert_se(r >= 0);

        unlink(t);
        unlink(p);
}

static void test_parse_multiline_env_file(void) {
        char    t[] = "/tmp/test-fileio-in-XXXXXX",
                p[] = "/tmp/test-fileio-out-XXXXXX";
        int fd, r;
        FILE *f;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        char **i;

        fd = mkostemp_safe(p, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        close(fd);

        fd = mkostemp_safe(t, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        f = fdopen(fd, "w");
        assert_se(f);

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

        r = load_env_file(NULL, t, NULL, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(streq_ptr(a[0], "one=BAR    VAR\tGAR"));
        assert_se(streq_ptr(a[1], "two=bar    var\tgar"));
        assert_se(streq_ptr(a[2], "tri=bar     var \tgar "));
        assert_se(a[3] == NULL);

        r = write_env_file(p, a);
        assert_se(r >= 0);

        r = load_env_file(NULL, p, NULL, &b);
        assert_se(r >= 0);

        unlink(t);
        unlink(p);
}


static void test_executable_is_script(void) {
        char t[] = "/tmp/test-executable-XXXXXX";
        int fd, r;
        FILE *f;
        char *command;

        fd = mkostemp_safe(t, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        f = fdopen(fd, "w");
        assert_se(f);

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

        fclose(f);
        unlink(t);
}

static void test_status_field(void) {
        _cleanup_free_ char *t = NULL, *p = NULL, *s = NULL, *z = NULL;
        unsigned long long total = 0, buffers = 0;
        int r;

        assert_se(get_status_field("/proc/self/status", "\nThreads:", &t) == 0);
        puts(t);
        assert_se(streq(t, "1"));

        r = get_status_field("/proc/meminfo", "MemTotal:", &p);
        if (r != -ENOENT) {
                assert(r == 0);
                puts(p);
                assert_se(safe_atollu(p, &total) == 0);
        }

        r = get_status_field("/proc/meminfo", "\nBuffers:", &s);
        if (r != -ENOENT) {
                assert(r == 0);
                puts(s);
                assert_se(safe_atollu(s, &buffers) == 0);
        }

        if (p && t)
                assert(buffers < total);

        /* Seccomp should be a good test for field full of zeros. */
        r = get_status_field("/proc/meminfo", "\nSeccomp:", &z);
        if (r != -ENOENT) {
                assert(r == 0);
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

                if (r == -ENOENT || r == -EPERM)
                        return;

                assert(r == 0);
                assert(*capeff);
                p = capeff[strspn(capeff, DIGITS "abcdefABCDEF")];
                assert(!p || isspace(p));
        }
}

int main(int argc, char *argv[]) {
        log_parse_environment();
        log_open();

        test_parse_env_file();
        test_parse_multiline_env_file();
        test_executable_is_script();
        test_status_field();
        test_capeff();

        return 0;
}
