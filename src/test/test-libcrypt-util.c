/* SPDX-License-Identifier: LGPL-2.1+ */

#include "strv.h"
#include "tests.h"
#include "libcrypt-util.h"

static void test_hash_password_full(void) {
        log_info("/* %s */", __func__);

        _cleanup_free_ void *cd_data = NULL;
        const char *i;
        int cd_size = 0;

        log_info("sizeof(struct crypt_data): %zu bytes", sizeof(struct crypt_data));

        for (unsigned c = 0; c < 2; c++)
                FOREACH_STRING(i, "abc123", "password", "s3cr3t") {
                        _cleanup_free_ char *hashed;

                        if (c == 0)
                                assert_se(hash_password_full(i, &cd_data, &cd_size, &hashed) == 0);
                        else
                                assert_se(hash_password_full(i, NULL, NULL, &hashed) == 0);
                        log_debug("\"%s\" → \"%s\"", i, hashed);
                        log_info("crypt_r[a] buffer size: %i bytes", cd_size);
                }
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_hash_password_full();

        return 0;
}
