/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "mkdir.h"
#include "os-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"

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

TEST(parse_extension_release) {
        /* Let's assume that we have a valid extension image */
        _cleanup_free_ char *id = NULL, *version_id = NULL, *foobar = NULL, *a = NULL, *b = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;

        int r = mkdtemp_malloc("/tmp/test-os-util.XXXXXX", &tempdir);
        if (r < 0)
                log_error_errno(r, "Failed to setup working directory: %m");

        assert_se(a = path_join(tempdir, "/usr/lib/extension-release.d/extension-release.test"));
        assert_se(mkdir_parents(a, 0777) >= 0);

        r = write_string_file(a, "ID=the-id  \n VERSION_ID=the-version-id", WRITE_STRING_FILE_CREATE);
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        assert_se(parse_extension_release(tempdir, IMAGE_SYSEXT, "test", false, "ID", &id, "VERSION_ID", &version_id) == 0);
        log_info("ID: %s VERSION_ID: %s", id, version_id);
        assert_se(streq(id, "the-id"));
        assert_se(streq(version_id, "the-version-id"));

        assert_se(b = path_join(tempdir, "/etc/extension-release.d/extension-release.tester"));
        assert_se(mkdir_parents(b, 0777) >= 0);

        r = write_string_file(b, "ID=\"ignored\" \n ID=\"the-id\" \n VERSION_ID='the-version-id'", WRITE_STRING_FILE_CREATE);
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        assert_se(parse_extension_release(tempdir, IMAGE_CONFEXT, "tester", false, "ID", &id, "VERSION_ID", &version_id) == 0);
        log_info("ID: %s VERSION_ID: %s", id, version_id);
        assert_se(streq(id, "the-id"));
        assert_se(streq(version_id, "the-version-id"));

        assert_se(parse_extension_release(tempdir, IMAGE_CONFEXT, "tester", false, "FOOBAR", &foobar) == 0);
        log_info("FOOBAR: %s", strnull(foobar));
        assert_se(foobar == NULL);

        assert_se(parse_extension_release(tempdir, IMAGE_SYSEXT, "test", false, "FOOBAR", &foobar) == 0);
        log_info("FOOBAR: %s", strnull(foobar));
        assert_se(foobar == NULL);
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

        assert_se(os_release_support_ended("1999-01-01", false, NULL) == true);
        assert_se(os_release_support_ended("2037-12-31", false, NULL) == false);
        assert_se(os_release_support_ended("-1-1-1", true, NULL) == -EINVAL);

        r = os_release_support_ended(NULL, false, NULL);
        if (r < 0)
                log_info_errno(r, "Failed to check host: %m");
        else
                log_info_errno(r, "Host is supported: %s", yes_no(!r));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
