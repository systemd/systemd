/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "fstab-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

/*
int fstab_filter_options(
        const char *opts,
        const char *names,
        const char **ret_namefound,
        const char **ret_value,
        const char **ret_values,
        char **ret_filtered);
*/

static void do_fstab_filter_options(const char *opts,
                                    const char *remove,
                                    int r_expected,
                                    int r_values_expected,
                                    const char *name_expected,
                                    const char *value_expected,
                                    const char *values_expected,
                                    const char *filtered_expected) {
        int r;
        const char *name;
        _cleanup_free_ char *value = NULL, *filtered = NULL, *joined = NULL;
        _cleanup_strv_free_ char **values = NULL;

        /* test mode which returns the last value */

        r = fstab_filter_options(opts, remove, &name, &value, NULL, &filtered);
        log_info("1: \"%s\" → %d, \"%s\", \"%s\", \"%s\", expected %d, \"%s\", \"%s\", \"%s\"",
                 opts, r, strnull(name), value, filtered,
                 r_expected, strnull(name_expected), strnull(value_expected), filtered_expected ?: opts);
        assert_se(r == r_expected);
        assert_se(streq_ptr(name, name_expected));
        assert_se(streq_ptr(value, value_expected));
        assert_se(streq_ptr(filtered, filtered_expected ?: opts));

        /* test mode which returns all the values */

        r = fstab_filter_options(opts, remove, &name, NULL, &values, NULL);
        assert_se(joined = strv_join(values, ":"));
        log_info("2: \"%s\" → %d, \"%s\", \"%s\", expected %d, \"%s\", \"%s\"",
                 opts, r, strnull(name), joined,
                 r_values_expected, strnull(name_expected), strnull(values_expected));
        assert_se(r == r_values_expected);
        assert_se(streq_ptr(name, r_values_expected > 0 ? name_expected : NULL));
        assert_se(streq_ptr(joined, values_expected));

        /* also test the malloc-less mode */
        r = fstab_filter_options(opts, remove, &name, NULL, NULL, NULL);
        log_info("3: \"%s\" → %d, \"%s\", expected %d, \"%s\"\n-",
                 opts, r, strnull(name),
                 r_expected, strnull(name_expected));
        assert_se(r == r_expected);
        assert_se(streq_ptr(name, name_expected));
}

TEST(fstab_filter_options) {
        do_fstab_filter_options("opt=0", "opt\0x-opt\0", 1, 1, "opt", "0", "0", "");
        do_fstab_filter_options("opt=0", "x-opt\0opt\0", 1, 1, "opt", "0", "0", "");
        do_fstab_filter_options("opt", "opt\0x-opt\0", 1, 0, "opt", NULL, "", "");
        do_fstab_filter_options("opt", "x-opt\0opt\0", 1, 0, "opt", NULL, "", "");
        do_fstab_filter_options("x-opt", "x-opt\0opt\0", 1, 0, "x-opt", NULL, "", "");

        do_fstab_filter_options("opt=0,other", "opt\0x-opt\0", 1, 1, "opt", "0", "0", "other");
        do_fstab_filter_options("opt=0,other", "x-opt\0opt\0", 1, 1, "opt", "0", "0", "other");
        do_fstab_filter_options("opt,other", "opt\0x-opt\0", 1, 0, "opt", NULL, "", "other");
        do_fstab_filter_options("opt,other", "x-opt\0opt\0", 1, 0, "opt", NULL, "", "other");
        do_fstab_filter_options("x-opt,other", "opt\0x-opt\0", 1, 0, "x-opt", NULL, "", "other");

        do_fstab_filter_options("opt=0\\,1,other", "opt\0x-opt\0", 1, 1, "opt", "0,1", "0,1", "other");
        do_fstab_filter_options("opt=0,other,x-opt\\,foobar", "x-opt\0opt\0", 1, 1, "opt", "0", "0", "other,x-opt\\,foobar");
        do_fstab_filter_options("opt,other,x-opt\\,part", "opt\0x-opt\0", 1, 0, "opt", NULL, "", "other,x-opt\\,part");
        do_fstab_filter_options("opt,other,part\\,x-opt", "x-opt\0opt\0", 1, 0, "opt", NULL, "", "other,part\\,x-opt");
        do_fstab_filter_options("opt,other\\,\\,\\,opt,x-part", "opt\0x-opt\0", 1, 0, "opt", NULL, "", "other\\,\\,\\,opt,x-part");

        do_fstab_filter_options("opto=0,other", "opt\0x-opt\0", 0, 0, NULL, NULL, "", NULL);
        do_fstab_filter_options("opto,other", "opt\0x-opt\0", 0, 0, NULL, NULL, "", NULL);
        do_fstab_filter_options("x-opto,other", "opt\0x-opt\0", 0, 0, NULL, NULL, "", NULL);

        do_fstab_filter_options("first,opt=0", "opt\0x-opt\0", 1, 1, "opt", "0", "0", "first");
        do_fstab_filter_options("first=1,opt=0", "opt\0x-opt\0", 1, 1, "opt", "0", "0", "first=1");
        do_fstab_filter_options("first,opt=", "opt\0x-opt\0", 1, 1, "opt", "", "", "first");
        do_fstab_filter_options("first=1,opt", "opt\0x-opt\0", 1, 0, "opt", NULL, "", "first=1");
        do_fstab_filter_options("first=1,x-opt", "opt\0x-opt\0", 1, 0, "x-opt", NULL, "", "first=1");

        do_fstab_filter_options("first,opt=0,last=1", "opt\0x-opt\0", 1, 1, "opt", "0", "0", "first,last=1");
        do_fstab_filter_options("first=1,opt=0,last=2", "x-opt\0opt\0", 1, 1, "opt", "0", "0", "first=1,last=2");
        do_fstab_filter_options("first,opt,last", "opt\0", 1, 0, "opt", NULL, "", "first,last");
        do_fstab_filter_options("first=1,opt,last", "x-opt\0opt\0", 1, 0, "opt", NULL, "", "first=1,last");
        do_fstab_filter_options("first=,opt,last", "opt\0noopt\0", 1, 0, "opt", NULL, "", "first=,last");

        /* check repeated options */
        do_fstab_filter_options("first,opt=0,noopt=1,last=1", "opt\0noopt\0", 1, 1, "noopt", "1", "0:1", "first,last=1");
        do_fstab_filter_options("first=1,opt=0,last=2,opt=1", "opt\0", 1, 1, "opt", "1", "0:1", "first=1,last=2");
        do_fstab_filter_options("x-opt=0,x-opt=1", "opt\0x-opt\0", 1, 1, "x-opt", "1", "0:1", "");
        do_fstab_filter_options("opt=0,x-opt=1", "opt\0x-opt\0", 1, 1, "x-opt", "1", "0:1", "");
        do_fstab_filter_options("opt=0,opt=1,opt=,opt=,opt=2", "opt\0noopt\0", 1, 1, "opt", "2", "0:1:::2", "");

        /* check that semicolons are not misinterpreted */
        do_fstab_filter_options("opt=0;", "opt\0", 1, 1, "opt", "0;", "0;", "");
        do_fstab_filter_options("opt;=0", "x-opt\0opt\0noopt\0x-noopt\0", 0, 0, NULL, NULL, "", NULL);
        do_fstab_filter_options("opt;", "opt\0x-opt\0", 0, 0, NULL, NULL, "", NULL);

        /* check that spaces are not misinterpreted */
        do_fstab_filter_options("opt=0 ", "opt\0", 1, 1, "opt", "0 ", "0 ", "");
        do_fstab_filter_options("opt =0", "x-opt\0opt\0noopt\0x-noopt\0", 0, 0, NULL, NULL, "", NULL);
        do_fstab_filter_options(" opt ", "opt\0x-opt\0", 0, 0, NULL, NULL, "", NULL);

        /* check function with NULL args */
        do_fstab_filter_options(NULL, "opt\0", 0, 0, NULL, NULL, "", "");
        do_fstab_filter_options("", "opt\0", 0, 0, NULL, NULL, "", "");

        /* unnecessary comma separators */
        do_fstab_filter_options("opt=x,,,,", "opt\0", 1, 1, "opt", "x", "x", "");
        do_fstab_filter_options(",,,opt=x,,,,", "opt\0", 1, 1, "opt", "x", "x", "");

        /* escaped characters */
        do_fstab_filter_options("opt1=\\\\,opt2=\\xff", "opt1\0", 1, 1, "opt1", "\\", "\\", "opt2=\\xff");
        do_fstab_filter_options("opt1=\\\\,opt2=\\xff", "opt2\0", 1, 1, "opt2", "\\xff", "\\xff", "opt1=\\");
}

TEST(fstab_find_pri) {
        int pri = -1;

        assert_se(fstab_find_pri("pri", &pri) == 0);
        assert_se(pri == -1);

        assert_se(fstab_find_pri("pri=11", &pri) == 1);
        assert_se(pri == 11);

        assert_se(fstab_find_pri("pri=-2", &pri) == 1);
        assert_se(pri == -2);

        assert_se(fstab_find_pri("opt,pri=12,opt", &pri) == 1);
        assert_se(pri == 12);

        assert_se(fstab_find_pri("opt,opt,pri=12,pri=13", &pri) == 1);
        assert_se(pri == 13);
}

TEST(fstab_yes_no_option) {
        assert_se(fstab_test_yes_no_option("nofail,fail,nofail", "nofail\0fail\0") == true);
        assert_se(fstab_test_yes_no_option("nofail,nofail,fail", "nofail\0fail\0") == false);
        assert_se(fstab_test_yes_no_option("abc,cde,afail", "nofail\0fail\0") == false);
        assert_se(fstab_test_yes_no_option("nofail,fail=0,nofail=0", "nofail\0fail\0") == true);
        assert_se(fstab_test_yes_no_option("nofail,nofail=0,fail=0", "nofail\0fail\0") == false);
}

TEST(fstab_node_to_udev_node) {
        char *n;

        n = fstab_node_to_udev_node("LABEL=applé/jack");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-label/applé\\x2fjack"));
        free(n);

        n = fstab_node_to_udev_node("PARTLABEL=pinkié pie");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-partlabel/pinkié\\x20pie"));
        free(n);

        n = fstab_node_to_udev_node("UUID=037b9d94-148e-4ee4-8d38-67bfe15bb535");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-uuid/037b9d94-148e-4ee4-8d38-67bfe15bb535"));
        free(n);

        n = fstab_node_to_udev_node("PARTUUID=037b9d94-148e-4ee4-8d38-67bfe15bb535");
        puts(n);
        assert_se(streq(n, "/dev/disk/by-partuuid/037b9d94-148e-4ee4-8d38-67bfe15bb535"));
        free(n);

        n = fstab_node_to_udev_node("PONIES=awesome");
        puts(n);
        assert_se(streq(n, "PONIES=awesome"));
        free(n);

        n = fstab_node_to_udev_node("/dev/xda1");
        puts(n);
        assert_se(streq(n, "/dev/xda1"));
        free(n);
}

DEFINE_TEST_MAIN(LOG_INFO);
