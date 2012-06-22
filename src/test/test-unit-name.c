/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include <stdlib.h>
#include <string.h>

#include "unit-name.h"
#include "util.h"

int main(int argc, char* argv[]) {
        char *t, *k;

        assert_se(t = unit_name_mangle("/home"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("/dev/sda"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("üxknürz.service"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("foobar-meh...waldi.service"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("_____####----.....service"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("_____##@;;;,,,##----.....service"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        assert_se(t = unit_name_mangle("xxx@@@@/////\\\\\\\\\\yyy.service"));
        assert_se(k = unit_name_mangle(t));
        puts(t);
        assert_se(streq(t, k));
        free(t);
        free(k);

        return 0;
}
