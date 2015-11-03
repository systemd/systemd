/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "string-util.h"

static void test_string_erase(void) {
        char *x;

        x = strdupa("");
        assert_se(streq(string_erase(x), ""));

        x = strdupa("1");
        assert_se(streq(string_erase(x), "x"));

        x = strdupa("12");
        assert_se(streq(string_erase(x), "xx"));

        x = strdupa("123");
        assert_se(streq(string_erase(x), "xxx"));

        x = strdupa("1234");
        assert_se(streq(string_erase(x), "xxxx"));

        x = strdupa("12345");
        assert_se(streq(string_erase(x), "xxxxx"));

        x = strdupa("123456");
        assert_se(streq(string_erase(x), "xxxxxx"));

        x = strdupa("1234567");
        assert_se(streq(string_erase(x), "xxxxxxx"));

        x = strdupa("12345678");
        assert_se(streq(string_erase(x), "xxxxxxxx"));

        x = strdupa("123456789");
        assert_se(streq(string_erase(x), "xxxxxxxxx"));
}

int main(int argc, char *argv[]) {
        test_string_erase();
        return 0;
}
