/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "discover-image.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "mkdir.h"
#include "os-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "runtime-scope.h"
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
#if SIZEOF_TIME_T == 4
        /* Dates past 2038 overflow time_t on 32-bit systems, so keep a safe date here. */
        ASSERT_FALSE(os_release_support_ended("2037-12-31", false, NULL));
#else
        ASSERT_FALSE(os_release_support_ended("9999-12-30", false, NULL));
#endif
        ASSERT_ERROR(os_release_support_ended("1-1-1", true, NULL), ERANGE);

        r = os_release_support_ended(NULL, false, NULL);
        if (r < 0)
                log_info_errno(r, "Failed to check host: %m");
        else
                log_info_errno(r, "Host is supported: %s", yes_no(!r));
}

static void test_path_extract_image_name_one(const char *path, const char *expected) {
        _cleanup_free_ char *name = NULL;

        ASSERT_OK_ZERO(path_extract_image_name(path, &name));
        ASSERT_STREQ(name, expected);
}

TEST(path_extract_image_name) {
        test_path_extract_image_name_one("foo.raw", "foo");
        test_path_extract_image_name_one("foo.raw.zst", "foo");
        test_path_extract_image_name_one("foo.sysext.raw", "foo");
        test_path_extract_image_name_one("foo.sysext.raw.zst", "foo");
        test_path_extract_image_name_one("foo.confext.raw", "foo");
        test_path_extract_image_name_one("foo.confext.raw.zst", "foo");
        test_path_extract_image_name_one("/var/lib/extensions/foo.raw", "foo");
        test_path_extract_image_name_one("/var/lib/extensions/foo.raw.zst", "foo");
        test_path_extract_image_name_one("/var/lib/confexts/bar.raw.zst", "bar");
        test_path_extract_image_name_one("foo_1.0.raw", "foo");
        test_path_extract_image_name_one("foo_1.0.raw.zst", "foo");
        test_path_extract_image_name_one("foo+2.raw.zst", "foo");
        test_path_extract_image_name_one("my-image.sysext.raw.zst", "my-image");
        test_path_extract_image_name_one("my-image.confext.raw.zst", "my-image");
}

TEST(image_discover_raw_zst) {
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        _cleanup_free_ char *ext_dir = NULL, *conf_dir = NULL;
        Image *img;

        ASSERT_OK_ZERO(mkdtemp_malloc("/tmp/test-discover-image.XXXXXX", &tempdir));

        assert_se(ext_dir = path_join(tempdir, "/var/lib/extensions"));
        ASSERT_OK_ZERO(mkdir_p(ext_dir, 0755));
        assert_se(conf_dir = path_join(tempdir, "/var/lib/confexts"));
        ASSERT_OK_ZERO(mkdir_p(conf_dir, 0755));

        _cleanup_free_ char *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
        assert_se(p1 = path_join(ext_dir, "ext1.raw"));
        ASSERT_OK_ZERO(touch(p1));
        assert_se(p2 = path_join(ext_dir, "ext2.raw.zst"));
        ASSERT_OK_ZERO(touch(p2));
        assert_se(p3 = path_join(ext_dir, "ext3.sysext.raw.zst"));
        ASSERT_OK_ZERO(touch(p3));
        assert_se(p4 = path_join(conf_dir, "conf1.confext.raw.zst"));
        ASSERT_OK_ZERO(touch(p4));

        ASSERT_OK_ZERO(image_discover(RUNTIME_SCOPE_SYSTEM, IMAGE_SYSEXT, tempdir, &images));
        ASSERT_NOT_NULL(img = hashmap_get(images, "ext1"));
        ASSERT_EQ(img->type, IMAGE_RAW);
        ASSERT_NOT_NULL(img = hashmap_get(images, "ext2"));
        ASSERT_EQ(img->type, IMAGE_RAW);
        ASSERT_NOT_NULL(img = hashmap_get(images, "ext3"));
        ASSERT_EQ(img->type, IMAGE_RAW);
        ASSERT_NULL(hashmap_get(images, "conf1"));

        images = hashmap_free(images);
        ASSERT_OK_ZERO(image_discover(RUNTIME_SCOPE_SYSTEM, IMAGE_CONFEXT, tempdir, &images));
        ASSERT_NOT_NULL(img = hashmap_get(images, "conf1"));
        ASSERT_EQ(img->type, IMAGE_RAW);
        ASSERT_NULL(hashmap_get(images, "ext1"));
        ASSERT_NULL(hashmap_get(images, "ext2"));
        ASSERT_NULL(hashmap_get(images, "ext3"));

        _cleanup_(image_unrefp) Image *found = NULL;
        ASSERT_OK_POSITIVE(image_find(RUNTIME_SCOPE_SYSTEM, IMAGE_SYSEXT, "ext2", tempdir, &found));
        ASSERT_EQ(found->type, IMAGE_RAW);
        ASSERT_STREQ(found->name, "ext2");
        ASSERT_TRUE(endswith(found->path, "ext2.raw.zst"));

        found = image_unref(found);
        ASSERT_OK_POSITIVE(image_find(RUNTIME_SCOPE_SYSTEM, IMAGE_SYSEXT, "ext3", tempdir, &found));
        ASSERT_EQ(found->type, IMAGE_RAW);
        ASSERT_STREQ(found->name, "ext3");
        ASSERT_TRUE(endswith(found->path, "ext3.sysext.raw.zst"));

        found = image_unref(found);
        ASSERT_OK_POSITIVE(image_find(RUNTIME_SCOPE_SYSTEM, IMAGE_CONFEXT, "conf1", tempdir, &found));
        ASSERT_EQ(found->type, IMAGE_RAW);
        ASSERT_STREQ(found->name, "conf1");
        ASSERT_TRUE(endswith(found->path, "conf1.confext.raw.zst"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
