/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "md5.h"
#include "tests.h"

static void test_md5_one(const char *input, const char *expect) {
        uint8_t result[MD5_DIGEST_SIZE + 3];

        log_debug("\"%s\" → %s", input, expect);

        _cleanup_free_ char *str = ASSERT_NOT_NULL(new(char, strlen(input) + 4));

        /* This tests unaligned buffers, and feeding the input in two parts. */

        for (size_t i = 0; i < 4; i++) {
                strcpy(str + i, input);

                for (size_t j = 0; j < 4; j++) {
                        size_t len = strlen(input), split = len / (j + 1);
                        _cleanup_free_ char *hex_result = NULL;
                        struct md5_ctx ctx;

                        md5_init_ctx(&ctx);
                        md5_process_bytes(str + i, split, &ctx);
                        md5_process_bytes(str + i + split, len - split, &ctx);
                        md5_finish_ctx(&ctx, result + j);

                        hex_result = hexmem(result + j, MD5_DIGEST_SIZE);
                        ASSERT_STREQ(hex_result, expect);
                }
        }
}

TEST(md5) {
        /* From RFC 1321, appendix A.5 */
        test_md5_one("", "d41d8cd98f00b204e9800998ecf8427e");
        test_md5_one("a", "0cc175b9c0f1b6a831c399e269772661");
        test_md5_one("abc", "900150983cd24fb0d6963f7d28e17f72");
        test_md5_one("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
        test_md5_one("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
        test_md5_one("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                     "d174ab98d277d9f5a5611c2c9f419d9f");
        test_md5_one("1234567890123456789012345678901234567890" "1234567890123456789012345678901234567890",
                     "57edf4a22be3c955ac49da2e2107b67a");
}

TEST(md5_long) {
        /* Results compared with output of 'head -c 1000000 /dev/zero | tr '\0' a | md5sum' */
        _cleanup_free_ char *s = ASSERT_NOT_NULL(malloc(1000000));
        uint8_t result[MD5_DIGEST_SIZE];
        struct md5_ctx ctx;

        memset(s, 'a', 1000000);

        md5_direct(s, 1000000, result);
        _cleanup_free_ char *hex = hexmem(result, sizeof(result));
        ASSERT_STREQ(hex, "7707d6ae4e027c70eea2a935c2296f21");

        /* The same in odd-sized chunks */
        md5_init_ctx(&ctx);
        for (size_t i = 0; i < 1000000; i += 77)
                md5_process_bytes(s + i, MIN((size_t) 77, 1000000 - i), &ctx);
        md5_finish_ctx(&ctx, result);
        hex = mfree(hex);
        hex = hexmem(result, sizeof(result));
        ASSERT_STREQ(hex, "7707d6ae4e027c70eea2a935c2296f21");
}

DEFINE_TEST_MAIN(LOG_INFO);
