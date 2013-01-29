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

#define expect(pattern, repl, expected)                            \
        {                                                          \
                char _cleanup_free_ *t =                           \
                        unit_name_replace_instance(pattern, repl); \
                puts(t);                                           \
                assert(streq(t, expected));                        \
        }

        expect("foo@.service", "waldo", "foo@waldo.service");
        expect("foo@xyz.service", "waldo", "foo@waldo.service");
        expect("xyz", "waldo", "xyz");
        expect("", "waldo", "");
        expect("foo.service", "waldo", "foo.service");
        expect(".service", "waldo", ".service");
        expect("foo@", "waldo", "foo@waldo");
        expect("@bar", "waldo", "@waldo");

        puts("-------------------------------------------------");
#undef expect
#define expect(path, suffix, expected)                             \
        {                                                          \
                char _cleanup_free_ *k, *t =                       \
                        unit_name_from_path(path, suffix);         \
                puts(t);                                           \
                k = unit_name_to_path(t);                          \
                puts(k);                                           \
                assert(streq(k, expected ? expected : path));     \
        }

        expect("/waldo", ".mount", NULL);
        expect("/waldo/quuix", ".mount", NULL);
        expect("/waldo/quuix/", ".mount", "/waldo/quuix");
        expect("/", ".mount", NULL);
        expect("///", ".mount", "/");

        puts("-------------------------------------------------");
#undef expect
#define expect(pattern, path, suffix, expected)                         \
        {                                                               \
                char _cleanup_free_ *t =                                \
                        unit_name_from_path_instance(pattern, path, suffix); \
                puts(t);                                                \
                assert(streq(t, expected));                             \
        }

        expect("waldo", "/waldo", ".mount", "waldo@waldo.mount");
        expect("waldo", "/waldo////quuix////", ".mount", "waldo@waldo-quuix.mount");
        expect("waldo", "/", ".mount", "waldo@-.mount");
        expect("wa--ldo", "/--", ".mount", "wa--ldo@\\x2d\\x2d.mount");

        puts("-------------------------------------------------");
#undef expect
#define expect(pattern)                                                 \
        {                                                               \
                char _cleanup_free_ *k, *t;                             \
                assert_se(t = unit_name_mangle(pattern));               \
                assert_se(k = unit_name_mangle(t));                     \
                puts(t);                                                \
                assert_se(streq(t, k));                                 \
        }

        expect("/home");
        expect("/dev/sda");
        expect("üxknürz.service");
        expect("foobar-meh...waldi.service");
        expect("_____####----.....service");
        expect("_____##@;;;,,,##----.....service");
        expect("xxx@@@@/////\\\\\\\\\\yyy.service");

        return 0;
}
