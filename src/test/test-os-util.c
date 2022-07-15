/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "fs-util.h"
#include "log.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(path_is_os_tree) {
        assert_se(path_is_os_tree("/") > 0);
        assert_se(path_is_os_tree("/etc") == 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

TEST(parse_os_release) {
        /* Let's assume that we're running in a valid system, so os-release is available */
        _cleanup_free_ char *id = NULL, *id2 = NULL, *name = NULL, *foobar = NULL;
        assert_se(parse_os_release(NULL, "ID", &id) == 0);
        log_info("ID: %s", id);

        assert_se(setenv("SYSTEMD_OS_RELEASE", "/dev/null", 1) == 0);
        assert_se(parse_os_release(NULL, "ID", &id2) == 0);
        log_info("ID: %s", strnull(id2));

        _cleanup_(unlink_tempfilep) char tmpfile[] = "/tmp/test-os-util.XXXXXX";
        assert_se(write_tmpfile(tmpfile,
                                "ID=the-id  \n"
                                "NAME=the-name") == 0);

        assert_se(setenv("SYSTEMD_OS_RELEASE", tmpfile, 1) == 0);
        assert_se(parse_os_release(NULL, "ID", &id, "NAME", &name) == 0);
        log_info("ID: %s NAME: %s", id, name);
        assert_se(streq(id, "the-id"));
        assert_se(streq(name, "the-name"));

        _cleanup_(unlink_tempfilep) char tmpfile2[] = "/tmp/test-os-util.XXXXXX";
        assert_se(write_tmpfile(tmpfile2,
                                "ID=\"ignored\"  \n"
                                "ID=\"the-id\"  \n"
                                "NAME='the-name'") == 0);

        assert_se(setenv("SYSTEMD_OS_RELEASE", tmpfile2, 1) == 0);
        assert_se(parse_os_release(NULL, "ID", &id, "NAME", &name) == 0);
        log_info("ID: %s NAME: %s", id, name);
        assert_se(streq(id, "the-id"));
        assert_se(streq(name, "the-name"));

        assert_se(parse_os_release(NULL, "FOOBAR", &foobar) == 0);
        log_info("FOOBAR: %s", strnull(foobar));
        assert_se(foobar == NULL);

        assert_se(unsetenv("SYSTEMD_OS_RELEASE") == 0);
}

TEST(load_os_release_pairs) {
        _cleanup_(unlink_tempfilep) char tmpfile[] = "/tmp/test-os-util.XXXXXX";
        assert_se(write_tmpfile(tmpfile,
                                "ID=\"ignored\"  \n"
                                "ID=\"the-id\"  \n"
                                "NAME='the-name'") == 0);

        assert_se(setenv("SYSTEMD_OS_RELEASE", tmpfile, 1) == 0);

        _cleanup_strv_free_ char **pairs = NULL;
        assert_se(load_os_release_pairs(NULL, &pairs) == 0);
        assert_se(strv_equal(pairs, STRV_MAKE("ID", "the-id",
                                              "NAME", "the-name")));

        assert_se(unsetenv("SYSTEMD_OS_RELEASE") == 0);
}

TEST(os_release_support_ended) {
        int r;

        assert_se(os_release_support_ended("1999-01-01", false) == true);
        assert_se(os_release_support_ended("2037-12-31", false) == false);
        assert_se(os_release_support_ended("-1-1-1", true) == -EINVAL);

        r = os_release_support_ended(NULL, false);
        if (r < 0)
                log_info_errno(r, "Failed to check host: %m");
        else
                log_info_errno(r, "Host is supported: %s", yes_no(!r));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
