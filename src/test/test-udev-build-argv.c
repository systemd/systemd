/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "udev.h"

static void test_udev_build_argv_one(const char *c) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *arg = NULL;
        char *argv[128], **p;
        int argc;
        size_t i;

        assert_se(a = strv_split_full(c, NULL, SPLIT_QUOTES | SPLIT_RELAX));

        assert_se(arg = strdup(c));
        assert_se(udev_build_argv(arg, &argc, argv) >= 0);

        log_info("command: %s", c);

        i = 0;
        log_info("strv_split:");
        STRV_FOREACH(p, a)
                log_info("argv[%zu] = '%s'", i++, *p);

        i = 0;
        log_info("udev_build_argv:");
        STRV_FOREACH(p, argv)
                log_info("argv[%zu] = '%s'", i++, *p);

        assert_se(strv_equal(argv, a));
        assert_se(argc == (int) strv_length(a));

}

static void test_udev_build_argv(void) {
        test_udev_build_argv_one("one   two   three");
        test_udev_build_argv_one("one   'two   three '  \" four five \"  'aaa bbb  ");
        test_udev_build_argv_one("/bin/echo -e \\101");
        test_udev_build_argv_one("/bin/echo -n special-device");
        test_udev_build_argv_one("/bin/echo -n special-device");
        test_udev_build_argv_one("/bin/echo test");
        test_udev_build_argv_one("/bin/echo -n test-%b");
        test_udev_build_argv_one("/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9");
        test_udev_build_argv_one("/bin/sh -c 'echo foo3 foo4 foo5 foo6 foo7 foo8 foo9 | sed  s/foo9/bar9/'");
        test_udev_build_argv_one("/bin/echo -n 'foo3 foo4'   'foo5   foo6   foo7 foo8'");
        test_udev_build_argv_one("/bin/sh -c 'printf %%s \\\"foo1 foo2\\\" | grep \\\"foo1 foo2\\\"'");
        test_udev_build_argv_one("/bin/sh -c \\\"printf %%s 'foo1 foo2' | grep 'foo1 foo2'\\\"");
        test_udev_build_argv_one("/bin/sh -c 'printf \\\"%%s %%s\\\" \\\"foo1 foo2\\\" \\\"foo3\\\"| grep \\\"foo1 foo2\\\"'");
        test_udev_build_argv_one("/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9");
        test_udev_build_argv_one("/bin/echo -n foo3 foo4 foo5 foo6 foo7 foo8 foo9");
        test_udev_build_argv_one("/bin/echo -n foo");
        test_udev_build_argv_one("/bin/echo -n usb-%b");
        test_udev_build_argv_one("/bin/echo -n scsi-%b");
        test_udev_build_argv_one("/bin/echo -n foo-%b");
        test_udev_build_argv_one("/bin/echo test");
        test_udev_build_argv_one("/bin/echo symlink test this");
        test_udev_build_argv_one("/bin/echo symlink test this");
        test_udev_build_argv_one("/bin/echo link test this");
        test_udev_build_argv_one("/bin/echo -n node link1 link2");
        test_udev_build_argv_one("/bin/echo -n node link1 link2 link3 link4");
        test_udev_build_argv_one("/usr/bin/test -b %N");
        test_udev_build_argv_one("/bin/echo -e name; (/usr/bin/badprogram)");
        test_udev_build_argv_one("/bin/echo -e \\xc3\\xbcber");
        test_udev_build_argv_one("/bin/echo -e \\xef\\xe8garbage");
        test_udev_build_argv_one("/bin/echo 1 1 0400");
        test_udev_build_argv_one("/bin/echo 0 0 0400letsdoabuffferoverflow0123456789012345789012345678901234567890");
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_udev_build_argv();

        return 0;
}
