/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "hmac.h"
#include "string-util.h"
#include "tests.h"

static void hmac_sha256_by_string(const char *key, const char *value, uint8_t res[static SHA256_DIGEST_SIZE]) {
        hmac_sha256(key, strlen(key), value, strlen(value), res);
}

TEST(hmac) {
        uint8_t result[SHA256_DIGEST_SIZE];
        char *hex_result = NULL;

        /* Results compared with output of 'echo -n "<input>" | openssl dgst -sha256 -hmac "<key>"' */

        hmac_sha256_by_string("waldo",
                              "",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "cadd5e42114351181f3abff477641d88efb57d2b5641a1e5c6d623363a6d3bad"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("waldo",
                              "baldohaldo",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "c47ad5031ba21605e52c6ca68090d66a2dd5ccf84efa4bace15361a8cba63cda"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("waldo",
                              "baldo haldo",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "4e8974ad6c08b98cc2519cd1e27aa7195769fcf86db1dd7ceaab4d44c490ad69"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("waldo",
                              "baldo 4e8974ad6c08b98cc2519cd1e27aa7195769fcf86db1dd7ceaab4d44c490ad69 haldo",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "039f3df430b19753ffb493e5b90708f75c5210b63c6bcbef3374eb3f0a3f97f7"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("4e8974ad6c08b98cc2519cd1e27aa7195769fcf86db1dd7ceaab4d44c490ad69",
                              "baldo haldo",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "c4cfaf48077cbb0bbd177a09e59ec4c248f4ca771503410f5b54b98d88d2f47b"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("4e8974ad6c08b98cc2519cd1e27aa7195769fcf86db1dd7ceaab4d44c490ad69",
                              "supercalifragilisticexpialidocious",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "2c059e7a63c4c3b23f47966a65fd2f8a2f5d7161e2e90d78ff68866b5c375cb7"));
        hex_result = mfree(hex_result);

        hmac_sha256_by_string("4e8974ad6c08b98cc2519cd1e27aa7195769fcf86db1dd7ceaab4d44c490ad69c47ad5031ba21605e52c6ca68090d66a2dd5ccf84efa4bace15361a8cba63cda",
                              "supercalifragilisticexpialidocious",
                              result);
        hex_result = hexmem(result, sizeof(result));
        assert_se(streq_ptr(hex_result, "1dd1d1d45b9d9f9673dc9983c968c46ff3168e03cfeb4156a219eba1af4cff5f"));
        hex_result = mfree(hex_result);
}

DEFINE_TEST_MAIN(LOG_INFO);
