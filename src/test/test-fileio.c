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

static void test_parse_env_file(void) {
        char t[] = "/tmp/test-parse-env-file-XXXXXX";
        int fd, r;
        FILE *f;
        _cleanup_free_ char *one = NULL, *two = NULL, *three = NULL, *four = NULL, *five = NULL,
                        *six = NULL, *seven = NULL, *eight = NULL, *nine = NULL, *ten = NULL;
        _cleanup_strv_free_ char **a = NULL, **b = NULL;
        char **i;
        unsigned k;

        fd = mkostemp(t, O_CLOEXEC);
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

        r = load_env_file(t, NULL, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: <%s>", *i);

        assert_se(streq(a[0], "one=BAR"));
        assert_se(streq(a[1], "two=bar"));
        assert_se(streq(a[2], "three=333\nxxxx"));
        assert_se(streq(a[3], "four=44\"44"));
        assert_se(streq(a[4], "five=55\'55FIVEcinco"));
        assert_se(streq(a[5], "six=seis sechs sis"));
        assert_se(streq(a[6], "seven=sevenval#nocomment"));
        assert_se(streq(a[7], "eight=eightval #nocomment"));
        assert_se(streq(a[8], "export nine=nineval"));
        assert_se(streq(a[9], "ten="));
        assert_se(a[10] == NULL);

        strv_env_clean_log(a, "/tmp/test-fileio");

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

        r = write_env_file("/tmp/test-fileio", a);
        assert_se(r >= 0);

        r = load_env_file("/tmp/test-fileio", NULL, &b);
        assert_se(r >= 0);

        unlink(t);
        unlink("/tmp/test-fileio");
}

int main(int argc, char *argv[]) {
        test_parse_env_file();
        return 0;
}
