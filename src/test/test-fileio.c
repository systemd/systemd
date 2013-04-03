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

static void test_parse_env_file(void) {
        char t[] = "/tmp/test-parse-env-file-XXXXXX";
        int fd, r;
        FILE *f;
        _cleanup_free_ char *one = NULL, *two = NULL, *three = NULL, *four = NULL, *five = NULL, *six = NULL, *seven = NULL;
        _cleanup_strv_free_ char **a = NULL;
        char **i;

        fd = mkostemp(t, O_CLOEXEC);
        assert_se(fd >= 0);

        f = fdopen(fd, "w");
        assert_se(f);

        fputs("one=BAR   \n"
              "# comment\n"
              " # comment \n"
              "  two   =   bar    \n"
              "invalid line\n"
              "three = \"333\n"
              "xxxx\"\n"
              "four = \'44\\\"44\'\n"
              "five = \'55\\\'55\' \"FIVE\" cinco   \n"
              "six = seis sechs\\\n"
              " sis\n"
              "seven=", f);

        fflush(f);
        fclose(f);

        r = parse_env_file(
                        t, NULL,
                       "one", &one,
                       "two", &two,
                       "three", &three,
                       "four", &four,
                       "five", &five,
                       "six", &six,
                       "seven", &seven,
                       NULL);

        assert_se(r >= 0);

        log_info("one=[%s]", strna(one));
        log_info("two=[%s]", strna(two));
        log_info("three=[%s]", strna(three));
        log_info("four=[%s]", strna(four));
        log_info("five=[%s]", strna(five));
        log_info("six=[%s]", strna(six));
        log_info("seven=[%s]", strna(seven));

        assert_se(streq(one, "BAR"));
        assert_se(streq(two, "bar"));
        assert_se(streq(three, "333\nxxxx"));
        assert_se(streq(four, "44\"44"));
        assert_se(streq(five, "55\'55FIVEcinco"));
        assert_se(streq(six, "seis sechs sis"));
        assert_se(seven == NULL);

        r = load_env_file(t, NULL, &a);
        assert_se(r >= 0);

        STRV_FOREACH(i, a)
                log_info("Got: %s", *i);

        unlink(t);
}

int main(int argc, char *argv[]) {
        test_parse_env_file();
        return 0;
}
