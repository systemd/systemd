/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Zbigniew Jędrzejewski-Szmek

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

#include "fstab-util.h"
#include "util.h"
#include "log.h"

/*
int fstab_filter_options(const char *opts, const char *names,
                         const char **namefound, char **value, char **filtered);
*/

static void do_fstab_filter_options(const char *opts,
                                      const char *remove,
                                      int r_expected,
                                      const char *name_expected,
                                      const char *value_expected,
                                      const char *filtered_expected) {

        int r;
        const char *name;
        _cleanup_free_ char *value, *filtered;

        r = fstab_filter_options(opts, remove, &name, &value, &filtered);
        log_info("\"%s\" → %d, \"%s\", \"%s\", \"%s\", expected %d, \"%s\", \"%s\", \"%s\"",
                 opts, r, name, value, filtered,
                 r_expected, name_expected, value_expected, filtered_expected ?: opts);
        assert_se(r == r_expected);
        assert_se(streq_ptr(name, name_expected));
        assert_se(streq_ptr(value, value_expected));
        assert_se(streq_ptr(filtered, filtered_expected ?: opts));

        /* also test the malloc-less mode */
        r = fstab_filter_options(opts, remove, &name, NULL, NULL);
        log_info("\"%s\" → %d, \"%s\", expected %d, \"%s\"",
                 opts, r, name,
                 r_expected, name_expected);
        assert_se(r == r_expected);
        assert_se(streq_ptr(name, name_expected));
}

static void test_fstab_filter_options(void) {
        do_fstab_filter_options("opt=0", "opt\0x-opt\0", 1, "opt", "0", "");
        do_fstab_filter_options("opt=0", "x-opt\0opt\0", 1, "opt", "0", "");
        do_fstab_filter_options("opt", "opt\0x-opt\0", 1, "opt", NULL, "");
        do_fstab_filter_options("opt", "x-opt\0opt\0", 1, "opt", NULL, "");
        do_fstab_filter_options("x-opt", "x-opt\0opt\0", 1, "x-opt", NULL, "");

        do_fstab_filter_options("opt=0,other", "opt\0x-opt\0", 1, "opt", "0", "other");
        do_fstab_filter_options("opt=0,other", "x-opt\0opt\0", 1, "opt", "0", "other");
        do_fstab_filter_options("opt,other", "opt\0x-opt\0", 1, "opt", NULL, "other");
        do_fstab_filter_options("opt,other", "x-opt\0opt\0", 1, "opt", NULL, "other");
        do_fstab_filter_options("x-opt,other", "opt\0x-opt\0", 1, "x-opt", NULL, "other");

        do_fstab_filter_options("opto=0,other", "opt\0x-opt\0", 0, NULL, NULL, NULL);
        do_fstab_filter_options("opto,other", "opt\0x-opt\0", 0, NULL, NULL, NULL);
        do_fstab_filter_options("x-opto,other", "opt\0x-opt\0", 0, NULL, NULL, NULL);

        do_fstab_filter_options("first,opt=0", "opt\0x-opt\0", 1, "opt", "0", "first");
        do_fstab_filter_options("first=1,opt=0", "opt\0x-opt\0", 1, "opt", "0", "first=1");
        do_fstab_filter_options("first,opt=", "opt\0x-opt\0", 1, "opt", "", "first");
        do_fstab_filter_options("first=1,opt", "opt\0x-opt\0", 1, "opt", NULL, "first=1");
        do_fstab_filter_options("first=1,x-opt", "opt\0x-opt\0", 1, "x-opt", NULL, "first=1");

        do_fstab_filter_options("first,opt=0,last=1", "opt\0x-opt\0", 1, "opt", "0", "first,last=1");
        do_fstab_filter_options("first=1,opt=0,last=2", "x-opt\0opt\0", 1, "opt", "0", "first=1,last=2");
        do_fstab_filter_options("first,opt,last", "opt\0", 1, "opt", NULL, "first,last");
        do_fstab_filter_options("first=1,opt,last", "x-opt\0opt\0", 1, "opt", NULL, "first=1,last");
        do_fstab_filter_options("first=,opt,last", "opt\0noopt\0", 1, "opt", NULL, "first=,last");

        /* check repeated options */
        do_fstab_filter_options("first,opt=0,noopt=1,last=1", "opt\0noopt\0", 1, "noopt", "1", "first,last=1");
        do_fstab_filter_options("first=1,opt=0,last=2,opt=1", "opt\0", 1, "opt", "1", "first=1,last=2");
        do_fstab_filter_options("x-opt=0,x-opt=1", "opt\0x-opt\0", 1, "x-opt", "1", "");
        do_fstab_filter_options("opt=0,x-opt=1", "opt\0x-opt\0", 1, "x-opt", "1", "");

        /* check that semicolons are not misinterpreted */
        do_fstab_filter_options("opt=0;", "opt\0", 1, "opt", "0;", "");
        do_fstab_filter_options("opt;=0", "x-opt\0opt\0noopt\0x-noopt\0", 0, NULL, NULL, NULL);
        do_fstab_filter_options("opt;", "opt\0x-opt\0", 0, NULL, NULL, NULL);

        /* check that spaces are not misinterpreted */
        do_fstab_filter_options("opt=0 ", "opt\0", 1, "opt", "0 ", "");
        do_fstab_filter_options("opt =0", "x-opt\0opt\0noopt\0x-noopt\0", 0, NULL, NULL, NULL);
        do_fstab_filter_options(" opt ", "opt\0x-opt\0", 0, NULL, NULL, NULL);

        /* check function will NULL args */
        do_fstab_filter_options(NULL, "opt\0", 0, NULL, NULL, "");
        do_fstab_filter_options("", "opt\0", 0, NULL, NULL, "");
}

static void test_fstab_find_pri(void) {
        int pri = -1;

        assert_se(fstab_find_pri("pri", &pri) == 0);
        assert_se(pri == -1);

        assert_se(fstab_find_pri("pri=11", &pri) == 1);
        assert_se(pri == 11);

        assert_se(fstab_find_pri("opt,pri=12,opt", &pri) == 1);
        assert_se(pri == 12);

        assert_se(fstab_find_pri("opt,opt,pri=12,pri=13", &pri) == 1);
        assert_se(pri == 13);
}

static void test_fstab_yes_no_option(void) {
        assert_se(fstab_test_yes_no_option("nofail,fail,nofail", "nofail\0fail\0") == true);
        assert_se(fstab_test_yes_no_option("nofail,nofail,fail", "nofail\0fail\0") == false);
        assert_se(fstab_test_yes_no_option("abc,cde,afail", "nofail\0fail\0") == false);
        assert_se(fstab_test_yes_no_option("nofail,fail=0,nofail=0", "nofail\0fail\0") == true);
        assert_se(fstab_test_yes_no_option("nofail,nofail=0,fail=0", "nofail\0fail\0") == false);
}

int main(void) {
        test_fstab_filter_options();
        test_fstab_find_pri();
        test_fstab_yes_no_option();
}
