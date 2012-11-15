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

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "install.h"
#include "util.h"
#include "macro.h"
#include "hashmap.h"
#include "load-fragment.h"

static void test_unit_file_get_set(void) {
        int r;
        Hashmap *h;
        Iterator i;
        UnitFileList *p;

        h = hashmap_new(string_hash_func, string_compare_func);
        assert(h);

        r = unit_file_get_list(UNIT_FILE_SYSTEM, NULL, h);
        log_info("unit_file_get_list: %s", strerror(-r));
        assert(r >= 0);

        HASHMAP_FOREACH(p, h, i)
                printf("%s = %s\n", p->path, unit_file_state_to_string(p->state));

        unit_file_list_free(h);
}

static void check_execcommand(ExecCommand *c,
                              const char* path,
                              const char* argv0,
                              const char* argv1,
                              bool ignore) {
        assert_se(c);
        log_info("%s %s %s %s",
                 c->path, c->argv[0], c->argv[1], c->argv[2]);
        assert_se(streq(c->path, path));
        assert_se(streq(c->argv[0], argv0));
        assert_se(streq(c->argv[1], argv1));
        assert_se(c->argv[2] == NULL);
        assert_se(c->ignore == ignore);
}

static void test_config_parse_exec(void) {
        /* int config_parse_exec( */
        /*         const char *filename, */
        /*         unsigned line, */
        /*         const char *section, */
        /*         const char *lvalue, */
        /*         int ltype, */
        /*         const char *rvalue, */
        /*         void *data, */
        /*         void *userdata) */
        int r;

        ExecCommand *c = NULL, *c1;

        /* basic test */
        r = config_parse_exec("fake", 1, "section",
                              "LValue", 0, "/RValue r1",
                              &c, NULL);
        assert_se(r >= 0);
        check_execcommand(c, "/RValue", "/RValue", "r1", false);

        r = config_parse_exec("fake", 2, "section",
                              "LValue", 0, "/RValue///slashes/// r1",
                              &c, NULL);
       /* test slashes */
        assert_se(r >= 0);
        c1 = c->command_next;
        check_execcommand(c1, "/RValue/slashes", "/RValue///slashes///",
                          "r1", false);

        /* honour_argv0 */
        r = config_parse_exec("fake", 3, "section",
                              "LValue", 0, "@/RValue///slashes2/// argv0 r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1, "/RValue/slashes2", "argv0", "r1", false);

        /* ignore && honour_argv0 */
        r = config_parse_exec("fake", 4, "section",
                              "LValue", 0, "-@/RValue///slashes3/// argv0a r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/RValue/slashes3", "argv0a", "r1", true);

        /* ignore && honour_argv0 */
        r = config_parse_exec("fake", 4, "section",
                              "LValue", 0, "@-/RValue///slashes4/// argv0b r1",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/RValue/slashes4", "argv0b", "r1", true);

        /* ignore && ignore */
        r = config_parse_exec("fake", 4, "section",
                              "LValue", 0, "--/RValue argv0 r1",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        /* ignore && ignore */
        r = config_parse_exec("fake", 4, "section",
                              "LValue", 0, "-@-/RValue argv0 r1",
                              &c, NULL);
        assert_se(r == 0);
        assert_se(c1->command_next == NULL);

        /* semicolon */
        r = config_parse_exec("fake", 5, "section",
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; "
                              "/goo/goo boo",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/RValue", "argv0", "r1", true);

        c1 = c1->command_next;
        check_execcommand(c1,
                          "/goo/goo", "/goo/goo", "boo", false);

        /* trailing semicolon */
        r = config_parse_exec("fake", 5, "section",
                              "LValue", 0,
                              "-@/RValue argv0 r1 ; ",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/RValue", "argv0", "r1", true);

        assert_se(c1->command_next == NULL);

        /* escaped semicolon */
        r = config_parse_exec("fake", 5, "section",
                              "LValue", 0,
                              "/usr/bin/find \\;",
                              &c, NULL);
        assert_se(r >= 0);
        c1 = c1->command_next;
        check_execcommand(c1,
                          "/usr/bin/find", "/usr/bin/find", ";", false);

        exec_command_free_list(c);
}

int main(int argc, char *argv[]) {

        test_unit_file_get_set();
        test_config_parse_exec();

        return 0;
}
