/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "oci-util.h"

static void test_urlescape_one(const char *s, const char *expected) {
        _cleanup_free_ char *t = ASSERT_PTR(urlescape(s));

        ASSERT_STREQ(t, expected);
}

TEST(urlescape) {
        test_urlescape_one(NULL, "");
        test_urlescape_one("", "");
        test_urlescape_one("a", "a");
        test_urlescape_one(" ", "%20");
        test_urlescape_one("     ", "%20%20%20%20%20");
        test_urlescape_one("foo\tfoo\aqux", "foo%09foo%07qux");
        test_urlescape_one("müffel", "m%c3%bcffel");
}

TEST(oci_registry_is_valid) {
        /* plain hostname — valid */
        ASSERT_OK_POSITIVE(oci_registry_is_valid("localhost"));
        ASSERT_OK_POSITIVE(oci_registry_is_valid("registry.example.com"));

        /* host:port — valid */
        ASSERT_OK_POSITIVE(oci_registry_is_valid("localhost:5000"));
        ASSERT_OK_POSITIVE(oci_registry_is_valid("registry.example.com:443"));
        ASSERT_OK_POSITIVE(oci_registry_is_valid("registry.io:1"));
        ASSERT_OK_POSITIVE(oci_registry_is_valid("registry.io:65535"));

        /* port 0 — invalid */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost:0"), 0);

        /* port overflow */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost:65536"), 0);

        /* non-decimal port forms — rejected */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost:0x50"), 0);   /* hex */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost:017"), 0);    /* leading zero */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost:+80"), 0);    /* plus sign */
        ASSERT_OK_EQ(oci_registry_is_valid("localhost: 80"), 0);    /* leading space */

        /* invalid hostname */
        ASSERT_OK_EQ(oci_registry_is_valid(":5000"), 0);
        ASSERT_OK_EQ(oci_registry_is_valid(""), 0);
        ASSERT_OK_EQ(oci_registry_is_valid(NULL), 0);
}

TEST(oci_ref_parse) {
        /* Validate tags */
        ASSERT_OK(oci_ref_parse("quay.io/fedora/fedora", /* ret_registry= */ NULL, /* ret_image= */ NULL, /* ret_tag= */ NULL));
        ASSERT_OK(oci_ref_parse("quay.io/fedora/fedora:latest", /* ret_registry= */ NULL, /* ret_image= */ NULL, /* ret_tag= */ NULL));
        ASSERT_OK(oci_ref_parse("quay.io:443/fedora/fedora", /* ret_registry= */ NULL, /* ret_image= */ NULL, /* ret_tag= */ NULL));
        ASSERT_OK(oci_ref_parse("quay.io:443/fedora/fedora:latest", /* ret_registry= */ NULL, /* ret_image= */ NULL, /* ret_tag= */ NULL));
}

TEST(oci_media_type) {
        ASSERT_TRUE(oci_media_type_is_index("application/vnd.oci.image.index.v1+json"));
        ASSERT_TRUE(oci_media_type_is_index("application/vnd.docker.distribution.manifest.list.v2+json"));
        ASSERT_FALSE(oci_media_type_is_index("application/vnd.oci.image.manifest.v1+json"));
        ASSERT_FALSE(oci_media_type_is_index(NULL));

        ASSERT_TRUE(oci_media_type_is_manifest("application/vnd.oci.image.manifest.v1+json"));
        ASSERT_TRUE(oci_media_type_is_manifest("application/vnd.docker.distribution.manifest.v2+json"));
        ASSERT_FALSE(oci_media_type_is_manifest("application/vnd.docker.distribution.manifest.v1+prettyjws"));
        ASSERT_FALSE(oci_media_type_is_manifest("application/vnd.oci.image.index.v1+json"));
        ASSERT_FALSE(oci_media_type_is_manifest(NULL));

        ASSERT_TRUE(oci_media_type_is_config("application/vnd.oci.image.config.v1+json"));
        ASSERT_TRUE(oci_media_type_is_config("application/vnd.docker.container.image.v1+json"));
        ASSERT_FALSE(oci_media_type_is_config("application/json"));

        ASSERT_TRUE(oci_media_type_is_layer("application/vnd.oci.image.layer.v1.tar"));
        ASSERT_TRUE(oci_media_type_is_layer("application/vnd.oci.image.layer.v1.tar+gzip"));
        ASSERT_TRUE(oci_media_type_is_layer("application/vnd.oci.image.layer.v1.tar+zstd"));
        ASSERT_TRUE(oci_media_type_is_layer("application/vnd.docker.image.rootfs.diff.tar.gzip"));
        ASSERT_FALSE(oci_media_type_is_layer("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"));
        ASSERT_FALSE(oci_media_type_is_layer("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
