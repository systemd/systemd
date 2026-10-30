/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "tests.h"

/* helpers for test_encode_devnode_name */
static char *do_encode_string(const char *in) {
        size_t out_len = strlen(in) * 4 + 1;
        char *out = malloc(out_len);

        ASSERT_NOT_NULL(out);
        ASSERT_OK(encode_devnode_name(in, out, out_len));
        puts(out);

        return out;
}

static bool expect_encoded_as(const char *in, const char *expected) {
        _cleanup_free_ char *encoded = do_encode_string(in);
        return streq(encoded, expected);
}

TEST(encode_devnode_name) {
        ASSERT_TRUE(expect_encoded_as("systemd sucks", "systemd\\x20sucks"));
        ASSERT_TRUE(expect_encoded_as("pinkiepie", "pinkiepie"));
        ASSERT_TRUE(expect_encoded_as("valíd\\ųtf8", "valíd\\x5cųtf8"));
        ASSERT_TRUE(expect_encoded_as("s/ash/ng", "s\\x2fash\\x2fng"));
        ASSERT_TRUE(expect_encoded_as("/", "\\x2f"));
        ASSERT_TRUE(expect_encoded_as("!", "\\x21"));
        ASSERT_TRUE(expect_encoded_as("QEMU    ", "QEMU\\x20\\x20\\x20\\x20"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
