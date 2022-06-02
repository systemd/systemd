/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "sha256.h"
#include "string-util.h"
#include "tests.h"

static void sha256_process_string(const char *key, struct sha256_ctx *ctx) {
        sha256_process_bytes(key, strlen(key), ctx);
}

static void test_sha256_one(const char *key, const char *expect) {
        uint8_t result[SHA256_DIGEST_SIZE + 3];
        _cleanup_free_ char *str = NULL;
        struct sha256_ctx ctx;

        log_debug("\"%s\" → %s", key, expect);

        assert_se(str = new(char, strlen(key) + 4));

        /* This tests unaligned buffers. */

        for (size_t i = 0; i < 4; i++) {
                strcpy(str + i, key);

                for (size_t j = 0; j < 4; j++) {
                        _cleanup_free_ char *hex_result = NULL;

                        sha256_init_ctx(&ctx);
                        sha256_process_string(str + i, &ctx);
                        sha256_finish_ctx(&ctx, result + j);

                        hex_result = hexmem(result + j, SHA256_DIGEST_SIZE);
                        assert_se(streq_ptr(hex_result, expect));
                }
        }
}

TEST(sha256) {
        /* Results compared with output of 'echo -n "<input>" | sha256sum -' */

        test_sha256_one("abcdefghijklmnopqrstuvwxyz",
                        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73");
        test_sha256_one("ほげほげあっちょんぶりけ",
                        "ce7225683653be3b74861c5a4323b6baf3c3ceb361413ca99e3a5b52c04411bd");
        test_sha256_one("0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
                        "9cfe7faff7054298ca87557e15a10262de8d3eee77827417fbdfea1c41b9ec23");
}

DEFINE_TEST_MAIN(LOG_INFO);
