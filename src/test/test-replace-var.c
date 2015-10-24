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

#include <string.h>

#include "macro.h"
#include "replace-var.h"
#include "string-util.h"
#include "util.h"

static char *lookup(const char *variable, void *userdata) {
        return strjoin("<<<", variable, ">>>", NULL);
}

int main(int argc, char *argv[]) {
        char *r;

        assert_se(r = replace_var("@@@foobar@xyz@HALLO@foobar@test@@testtest@TEST@...@@@", lookup, NULL));
        puts(r);
        assert_se(streq(r, "@@@foobar@xyz<<<HALLO>>>foobar@test@@testtest<<<TEST>>>...@@@"));
        free(r);

        assert_se(r = strreplace("XYZFFFFXYZFFFFXYZ", "XYZ", "ABC"));
        puts(r);
        assert_se(streq(r, "ABCFFFFABCFFFFABC"));
        free(r);

        return 0;
}
