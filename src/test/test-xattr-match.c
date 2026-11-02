/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-json.h"

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "host-properties.h"
#include "xattr-match.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uapi16-manifest.h"
#include "xattr-util.h"

#define TEST_MACHINE_ID SD_ID128_MAKE(4b,1f,7c,95,0d,4f,4e,1a,9e,8f,3d,22,57,61,80,a3)

static void host_init(HostProperties *h) {
        *h = HOST_PROPERTIES_NULL;
        ASSERT_NOT_NULL(h->hostname = strdup("foo.example.com"));
        h->machine_id = TEST_MACHINE_ID;
        ASSERT_NOT_NULL(h->machine_tags = strv_new("rack=7", "server"));
        ASSERT_NOT_NULL(h->os_id = strdup("fedora"));
        ASSERT_NOT_NULL(h->os_version_id = strdup("42"));
        ASSERT_NOT_NULL(h->image_id = strdup("myos"));
        ASSERT_NOT_NULL(h->image_version = strdup("1.5"));
        h->loaded = true;
}

#define test_one(m, h, ...) xattr_match_test_strv(m, STRV_MAKE(__VA_ARGS__), h)

TEST(xattr_match_string_table) {
        for (XAttrMatch m = 0; m < _XATTR_MATCH_MAX; m++) {
                ASSERT_EQ(xattr_match_from_string(xattr_match_to_string(m)), m);
                ASSERT_TRUE(startswith(xattr_match_to_xattr_name(m), "uapi.match_"));
        }

        ASSERT_EQ(xattr_match_from_string("machine-id"), XATTR_MATCH_MACHINE_ID);
        ASSERT_EQ(xattr_match_from_string("os-version-id"), XATTR_MATCH_OS_VERSION_ID);
        ASSERT_STREQ(xattr_match_to_xattr_name(XATTR_MATCH_OS_VERSION_ID), "uapi.match_os_version_id");
        ASSERT_ERROR(xattr_match_from_string("foo"), EINVAL);
}

TEST(xattr_match_entry_is_valid) {
        ASSERT_TRUE(xattr_match_entry_is_valid(XATTR_MATCH_HOSTNAME, "foo*"));
        ASSERT_TRUE(xattr_match_entry_is_valid(XATTR_MATCH_HOSTNAME, ">="));
        ASSERT_FALSE(xattr_match_entry_is_valid(XATTR_MATCH_HOSTNAME, ""));
        ASSERT_FALSE(xattr_match_entry_is_valid(XATTR_MATCH_HOSTNAME, NULL));
        ASSERT_FALSE(xattr_match_entry_is_valid(XATTR_MATCH_MACHINE_TAGS, "\xff"));
        ASSERT_TRUE(xattr_match_entry_is_valid(XATTR_MATCH_OS_VERSION_ID, ">=40"));
        ASSERT_TRUE(xattr_match_entry_is_valid(XATTR_MATCH_OS_VERSION_ID, ">= 40"));
        ASSERT_TRUE(xattr_match_entry_is_valid(XATTR_MATCH_IMAGE_VERSION, "4*"));
        ASSERT_FALSE(xattr_match_entry_is_valid(XATTR_MATCH_IMAGE_VERSION, ">="));
        ASSERT_FALSE(xattr_match_entry_is_valid(XATTR_MATCH_IMAGE_VERSION, "<  "));
}

TEST(xattr_match_test_strv) {
        _cleanup_(host_properties_done) HostProperties h;
        host_init(&h);

        /* Globs, any must match */
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_HOSTNAME, &h, "foo.example.com"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_HOSTNAME, &h, "bar", "foo.*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_HOSTNAME, &h, "bar", "foo"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_MACHINE_ID, &h, "4b1f7c950d4f4e1a9e8f3d22576180a3"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_MACHINE_ID, &h, "00000000000000000000000000000000", "4b1f*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_MACHINE_ID, &h, "4B1F7C950D4F4E1A9E8F3D22576180A3"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_OS_ID, &h, "debian", "fedora"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_OS_ID, &h, "debian"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_IMAGE_ID, &h, "my*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_IMAGE_ID, &h, "other"));

        /* Machine tags, any pattern matching any tag */
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_MACHINE_TAGS, &h, "server"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_MACHINE_TAGS, &h, "client", "rack=*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_MACHINE_TAGS, &h, "client", "rack=8"));

        /* Version expressions, all must hold */
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">=1.2", "<2"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_IMAGE_VERSION, &h, "1.*"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_IMAGE_VERSION, &h, "=1.5"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_IMAGE_VERSION, &h, "!=1.4"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">=1.2", "<1.5"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">1.5"));
        ASSERT_OK_POSITIVE(test_one(XATTR_MATCH_OS_VERSION_ID, &h, ">=40"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_OS_VERSION_ID, &h, "<=41"));

        /* Invalid entries are refused, even if another entry already decided the result */
        ASSERT_ERROR(test_one(XATTR_MATCH_HOSTNAME, &h, ""), EINVAL);
        ASSERT_ERROR(test_one(XATTR_MATCH_HOSTNAME, &h, "foo.example.com", ""), EINVAL);
        ASSERT_ERROR(test_one(XATTR_MATCH_HOSTNAME, &h, "\xff"), EINVAL);
        ASSERT_ERROR(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">="), EINVAL);
        ASSERT_ERROR(test_one(XATTR_MATCH_IMAGE_VERSION, &h, "<1", ">= "), EINVAL);
        ASSERT_ERROR(xattr_match_test_strv(XATTR_MATCH_HOSTNAME, STRV_EMPTY, &h), EINVAL);

        /* Host properties that are not set never match */
        h.hostname = mfree(h.hostname);
        h.machine_id = SD_ID128_NULL;
        h.machine_tags = strv_free(h.machine_tags);
        h.image_version = mfree(h.image_version);
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_HOSTNAME, &h, "*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_MACHINE_ID, &h, "*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_MACHINE_TAGS, &h, "*"));
        ASSERT_OK_ZERO(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">=0"));
        ASSERT_ERROR(test_one(XATTR_MATCH_IMAGE_VERSION, &h, ">="), EINVAL);
}

static void parse_object(const char *json, Uapi16Object *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_parse(json, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_OK(dispatch_uapi16_object(v, /* n= */ 1, /* flags= */ 0, ret));
}

TEST(xattr_match_filter_test_uapi16_object) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        /* A root to load the host properties from */
        ASSERT_OK(tfd = mkdtemp_open(NULL, O_PATH, &t));
        ASSERT_OK_ERRNO(mkdirat(tfd, "etc", 0755));
        ASSERT_OK(write_string_file_at(tfd, "etc/hostname", "foo.example.com", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(tfd, "etc/machine-id", "4b1f7c950d4f4e1a9e8f3d22576180a3", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(tfd, "etc/machine-info", "TAGS=server:rack=7", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(tfd, "etc/os-release", "ID=fedora\nVERSION_ID=42\nIMAGE_ID=myos\nIMAGE_VERSION=1.5", WRITE_STRING_FILE_CREATE));

        _cleanup_(host_properties_done) HostProperties h = HOST_PROPERTIES_NULL;
        XAttrMatchFilter f = {
                .mask = XATTR_MATCH_MASK_ALL,
                .host = &h,
                .root = t,
        };

        /* Objects without any of the extended attributes are unrestricted, and the host properties are not
         * loaded for them */
        _cleanup_(uapi16_object_done) Uapi16Object o1 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"a.raw\"}", &o1);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(&f, &o1));

        _cleanup_(uapi16_object_done) Uapi16Object o2 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"b.raw\",\"extendedAttributes\":{\"user\":{\"foo\":{\"text\":\"bar\"}}}}", &o2);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(&f, &o2));
        ASSERT_FALSE(h.loaded);

        /* Disabled matches are not looked at either */
        _cleanup_(uapi16_object_done) Uapi16Object o3 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"c.raw\",\"extendedAttributes\":{\"user\":{\"uapi.match_hostname\":{\"base64\":\"b3RoZXJob3N0AA==\"}}}}", &o3);
        f.mask = XATTR_MATCH_MASK(XATTR_MATCH_OS_ID);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(&f, &o3));
        ASSERT_FALSE(h.loaded);

        /* But once there's something to match, they are */
        f.mask = XATTR_MATCH_MASK_ALL;
        ASSERT_OK_ZERO(xattr_match_filter_test_uapi16_object(&f, &o3));
        ASSERT_TRUE(h.loaded);
        ASSERT_STREQ(h.hostname, "foo.example.com");
        ASSERT_TRUE(sd_id128_equal(h.machine_id, TEST_MACHINE_ID));
        ASSERT_TRUE(strv_equal(h.machine_tags, STRV_MAKE("rack=7", "server")));
        ASSERT_STREQ(h.os_id, "fedora");
        ASSERT_STREQ(h.os_version_id, "42");
        ASSERT_STREQ(h.image_id, "myos");
        ASSERT_STREQ(h.image_version, "1.5");

        /* NUL separated lists, as well as plain strings, which are a list with a single entry */
        _cleanup_(uapi16_object_done) Uapi16Object o4 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"d.raw\",\"extendedAttributes\":{\"user\":{"
                     "\"uapi.match_hostname\":{\"base64\":\"YmFyAGZvby4qAA==\"},"
                     "\"uapi.match_image_version\":{\"base64\":\"Pj0xLjIAPDIA\"},"
                     "\"uapi.match_os_id\":{\"text\":\"fedora\"}}}}", &o4);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(&f, &o4));

        /* All enabled matches must match */
        _cleanup_(uapi16_object_done) Uapi16Object o5 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"e.raw\",\"extendedAttributes\":{\"user\":{"
                     "\"uapi.match_hostname\":{\"base64\":\"YmFyAGZvby4qAA==\"},"
                     "\"uapi.match_os_id\":{\"text\":\"debian\"}}}}", &o5);
        ASSERT_OK_ZERO(xattr_match_filter_test_uapi16_object(&f, &o5));
        f.mask &= ~XATTR_MATCH_MASK(XATTR_MATCH_OS_ID);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(&f, &o5));

        /* Invalid values make the instance unsuitable */
        _cleanup_(uapi16_object_done) Uapi16Object o6 = UAPI16_OBJECT_NULL;
        parse_object("{\"name\":\"f.raw\",\"extendedAttributes\":{\"user\":{\"uapi.match_hostname\":{\"text\":\"\"}}}}", &o6);
        ASSERT_OK_ZERO(xattr_match_filter_test_uapi16_object(&f, &o6));

        /* No mask, no filtering */
        ASSERT_OK_POSITIVE(xattr_match_filter_test_uapi16_object(NULL, &o5));
}

TEST(host_properties_load_symlinks) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;

        /* Absolute and relative symlinks are resolved below the root, not on the host */
        ASSERT_OK(tfd = mkdtemp_open(NULL, O_PATH, &t));
        ASSERT_OK_ERRNO(mkdirat(tfd, "etc", 0755));
        ASSERT_OK(write_string_file_at(tfd, "etc/hostname.real", "inroot.example.com", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("/etc/hostname.real", tfd, "etc/hostname"));
        ASSERT_OK(write_string_file_at(tfd, "etc/machine-info.real", "TAGS=inroot", WRITE_STRING_FILE_CREATE));
        ASSERT_OK_ERRNO(symlinkat("../../../../../../../../etc/machine-info.real", tfd, "etc/machine-info"));

        _cleanup_(host_properties_done) HostProperties h = HOST_PROPERTIES_NULL;
        ASSERT_OK(host_properties_load(&h, t));
        ASSERT_STREQ(h.hostname, "inroot.example.com");
        ASSERT_TRUE(strv_equal(h.machine_tags, STRV_MAKE("inroot")));
        ASSERT_TRUE(sd_id128_is_null(h.machine_id));
        ASSERT_NULL(h.os_id);
}

TEST(xattr_match_filter_test_inode) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        int r;

        ASSERT_OK(tfd = mkdtemp_open(NULL, O_DIRECTORY|O_CLOEXEC, &t));
        ASSERT_OK(write_string_file_at(tfd, "plain", "x", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(tfd, "mine", "x", WRITE_STRING_FILE_CREATE));
        ASSERT_OK(write_string_file_at(tfd, "other", "x", WRITE_STRING_FILE_CREATE));

        r = xsetxattr_strv(tfd, "mine", /* at_flags= */ 0, "user.uapi.match_os_id", STRV_MAKE("debian", "fedora"));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "File system does not support user extended attributes");
        ASSERT_OK(r);
        ASSERT_OK(xsetxattr_strv(tfd, "other", /* at_flags= */ 0, "user.uapi.match_os_id", STRV_MAKE("debian")));

        _cleanup_(host_properties_done) HostProperties h;
        host_init(&h);
        XAttrMatchFilter f = {
                .mask = XATTR_MATCH_MASK(XATTR_MATCH_OS_ID),
                .host = &h,
        };

        ASSERT_OK_POSITIVE(xattr_match_filter_test_inode(&f, tfd, "plain"));
        ASSERT_OK_POSITIVE(xattr_match_filter_test_inode(&f, tfd, "mine"));
        ASSERT_OK_ZERO(xattr_match_filter_test_inode(&f, tfd, "other"));

        f.mask = XATTR_MATCH_MASK(XATTR_MATCH_HOSTNAME);
        ASSERT_OK_POSITIVE(xattr_match_filter_test_inode(&f, tfd, "other"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
