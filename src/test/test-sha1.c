/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "sha1-fundamental.h"
#include "string-util.h"
#include "tests.h"

static void sha1_process_string(const char *key, struct sha1_ctx *ctx) {
        sha1_process_bytes(key, strlen(key), ctx);
}

static void test_sha1_one(const char *key, const char *expect) {
        uint8_t result[SHA1_DIGEST_SIZE + 3];
        _cleanup_free_ char *str = NULL;
        struct sha1_ctx ctx;

        log_debug("\"%s\" → %s", key, expect);

        assert_se(str = new(char, strlen(key) + 4));

        /* This tests unaligned buffers. */

        for (size_t i = 0; i < 4; i++) {
                strcpy(str + i, key);

                for (size_t j = 0; j < 4; j++) {
                        _cleanup_free_ char *hex_result = NULL;

                        sha1_init_ctx(&ctx);
                        sha1_process_string(str + i, &ctx);
                        sha1_finish_ctx(&ctx, result + j);

                        hex_result = hexmem(result + j, SHA1_DIGEST_SIZE);
                        ASSERT_STREQ(hex_result, expect);
                }
        }
}

/* From https://datatracker.ietf.org/doc/html/rfc3174#section-7.3 */
#define TEST1   "abc"
#define RESULT1 "a9993e364706816aba3e25717850c26c9cd0d89d"
#define TEST2   "abcdbcdecdefdefgefghfghighijhi" "jkijkljklmklmnlmnomnopnopq"
#define RESULT2 "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
#define TEST3   "a"
#define RESULT3 "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
#define TEST4   "01234567012345670123456701234567" "01234567012345670123456701234567"
#define RESULT4 "e0c094e867ef46c350ef54a7f59dd60bed92ae83"

TEST(sha1) {
        /* Results compared with output of 'echo -n "<input>" | sha1sum -' */

        test_sha1_one(TEST1, RESULT1);
        test_sha1_one(TEST2, RESULT2);
        test_sha1_one(TEST3, RESULT3);
        test_sha1_one(TEST4, RESULT4);
}

DEFINE_TEST_MAIN(LOG_INFO);
