/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "journal-compression-util.h"
#include "journal-header-util.h"
#include "tests.h"

TEST(header_put) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *headers = NULL;

        ASSERT_OK_POSITIVE(header_put(&headers, "NewName", "Val"));
        ASSERT_OK_POSITIVE(header_put(&headers, "Name", "FirstName"));
        ASSERT_OK_POSITIVE(header_put(&headers, "Name", "Override"));
        ASSERT_OK_ZERO(header_put(&headers, "Name", "FirstName"));
        ASSERT_ERROR(header_put(&headers, "InvalidN@me", "test"), EINVAL);
        ASSERT_ERROR(header_put(&headers, "Name", NULL), EINVAL);
        ASSERT_ERROR(header_put(&headers, NULL, "Value"), EINVAL);
        ASSERT_OK_POSITIVE(header_put(&headers, "Name", ""));
        ASSERT_ERROR(header_put(&headers, "", "Value"), EINVAL);
}

TEST(compression_none_then_algorithm) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *configs = NULL;
        Compression compression = COMPRESSION_NONE;

        for (Compression c = 1; c < _COMPRESSION_MAX; c++)
                if (compression_supported(c)) {
                        compression = c;
                        break;
                }

        if (compression == COMPRESSION_NONE)
                return (void) log_tests_skipped("No compression algorithm supported");

        ASSERT_OK_POSITIVE(config_parse_compression(
                        "test", "test.conf", 1, "Upload", 1, "Compression", false, "no", &configs, NULL));
        ASSERT_TRUE(ordered_hashmap_contains(configs, INT_TO_PTR(COMPRESSION_NONE)));

        ASSERT_OK_POSITIVE(config_parse_compression(
                        "test", "test.conf", 2, "Upload", 1, "Compression", false,
                        compression_to_string(compression), &configs, NULL));
        ASSERT_FALSE(ordered_hashmap_contains(configs, INT_TO_PTR(COMPRESSION_NONE)));
        ASSERT_NOT_NULL(ordered_hashmap_get(configs, INT_TO_PTR(compression)));

        ASSERT_OK(compression_configs_mangle(&configs));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
