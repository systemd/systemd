/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "fileio.h"
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
        ASSERT_GT(path_is_os_tree("/"), 0);
        ASSERT_EQ(path_is_os_tree("/etc"), 0);
        assert_se(path_is_os_tree("/idontexist") == -ENOENT);
}

TEST(parse_os_release) {
        _cleanup_free_ char *id = NULL, *id2 = NULL, *name = NULL, *foobar = NULL;

        if (access("/etc/os-release", F_OK) >= 0 || access("/usr/lib/os-release", F_OK) >= 0) {
                ASSERT_EQ(parse_os_release(NULL, "ID", &id), 0);
                log_info("ID: %s", id);
        }

        ASSERT_OK_ERRNO(setenv("SYSTEMD_OS_RELEASE", "/dev/null", 1));
        ASSERT_EQ(parse_os_release(NULL, "ID", &id2), 0);
        log_info("ID: %s", strnull(id2));

        _cleanup_(unlink_tempfilep) char tmpfile[] = "/tmp/test-os-util.XXXXXX";
        ASSERT_EQ(write_tmpfile(tmpfile,
                                "ID=the-id  \n"
                                "NAME=the-name"), 0);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_OS_RELEASE", tmpfile, 1));
        ASSERT_EQ(parse_os_release(NULL, "ID", &id, "NAME", &name), 0);
        log_info("ID: %s NAME: %s", id, name);
        ASSERT_STREQ(id, "the-id");
        ASSERT_STREQ(name, "the-name");

        _cleanup_(unlink_tempfilep) char tmpfile2[] = "/tmp/test-os-util.XXXXXX";
        ASSERT_EQ(write_tmpfile(tmpfile2,
                                "ID=\"ignored\"  \n"
                                "ID=\"the-id\"  \n"
                                "NAME='the-name'"), 0);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_OS_RELEASE", tmpfile2, 1));
        ASSERT_EQ(parse_os_release(NULL, "ID", &id, "NAME", &name), 0);
        log_info("ID: %s NAME: %s", id, name);
        ASSERT_STREQ(id, "the-id");
        ASSERT_STREQ(name, "the-name");

        ASSERT_EQ(parse_os_release(NULL, "FOOBAR", &foobar), 0);
        log_info("FOOBAR: %s", strnull(foobar));
        ASSERT_NULL(foobar);

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_OS_RELEASE"));
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
        ASSERT_GE(mkdir_parents(a, 0777), 0);

        r = write_string_file(a, "ID=the-id  \n VERSION_ID=the-version-id", WRITE_STRING_FILE_CREATE);
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        assert_se(parse_extension_release(tempdir, IMAGE_SYSEXT, "test", false, "ID", &id, "VERSION_ID", &version_id) == 0);
        log_info("ID: %s VERSION_ID: %s", id, version_id);
        ASSERT_STREQ(id, "the-id");
        ASSERT_STREQ(version_id, "the-version-id");

        assert_se(b = path_join(tempdir, "/etc/extension-release.d/extension-release.tester"));
        assert_se(mkdir_parents(b, 0777) >= 0);

        r = write_string_file(b, "ID=\"ignored\" \n ID=\"the-id\" \n VERSION_ID='the-version-id'", WRITE_STRING_FILE_CREATE);
        if (r < 0)
                log_error_errno(r, "Failed to write file: %m");

        ASSERT_EQ(parse_extension_release(tempdir, IMAGE_CONFEXT, "tester", false, "ID", &id, "VERSION_ID", &version_id), 0);
        log_info("ID: %s VERSION_ID: %s", id, version_id);
        ASSERT_STREQ(id, "the-id");
        ASSERT_STREQ(version_id, "the-version-id");

        assert_se(parse_extension_release(tempdir, IMAGE_CONFEXT, "tester", false, "FOOBAR", &foobar) == 0);
        log_info("FOOBAR: %s", strnull(foobar));
        ASSERT_NULL(foobar);

        assert_se(parse_extension_release(tempdir, IMAGE_SYSEXT, "test", false, "FOOBAR", &foobar) == 0);
        log_info("FOOBAR: %s", strnull(foobar));
        ASSERT_NULL(foobar);
}

TEST(load_os_release_pairs) {
        _cleanup_(unlink_tempfilep) char tmpfile[] = "/tmp/test-os-util.XXXXXX";
        ASSERT_EQ(write_tmpfile(tmpfile,
                                "ID=\"ignored\"  \n"
                                "ID=\"the-id\"  \n"
                                "NAME='the-name'"), 0);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_OS_RELEASE", tmpfile, 1));

        _cleanup_strv_free_ char **pairs = NULL;
        ASSERT_EQ(load_os_release_pairs(NULL, &pairs), 0);
        assert_se(strv_equal(pairs, STRV_MAKE("ID", "the-id",
                                              "NAME", "the-name")));

        ASSERT_OK_ERRNO(unsetenv("SYSTEMD_OS_RELEASE"));
}

TEST(os_release_support_ended) {
        int r;

        ASSERT_TRUE(os_release_support_ended("1999-01-01", false, NULL));
        ASSERT_FALSE(os_release_support_ended("2037-12-31", false, NULL));
#ifdef __GLIBC__
        ASSERT_ERROR(os_release_support_ended("-1-1-1", true, NULL), EINVAL);
#else
        ASSERT_ERROR(os_release_support_ended("-1-1-1", true, NULL), ERANGE);
#endif

        r = os_release_support_ended(NULL, false, NULL);
        if (r < 0)
                log_info_errno(r, "Failed to check host: %m");
        else
                log_info_errno(r, "Host is supported: %s", yes_no(!r));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
