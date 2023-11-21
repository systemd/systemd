/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "iovec-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"

TEST(read_credential_strings) {
        _cleanup_free_ char *x = NULL, *y = NULL, *saved = NULL, *p = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        const char *e = getenv("CREDENTIALS_DIRECTORY");
        if (e)
                assert_se(saved = strdup(e));

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) == 0);
        assert_se(x == NULL);
        assert_se(y == NULL);

        assert_se(mkdtemp_malloc(NULL, &tmp) >= 0);

        assert_se(setenv("CREDENTIALS_DIRECTORY", tmp, /* override= */ true) >= 0);

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) == 0);
        assert_se(x == NULL);
        assert_se(y == NULL);

        assert_se(p = path_join(tmp, "bar"));
        assert_se(write_string_file(p, "piff", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) == 0);
        assert_se(x == NULL);
        assert_se(streq(y, "piff"));

        assert_se(write_string_file(p, "paff", WRITE_STRING_FILE_TRUNCATE|WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) == 0);
        assert_se(x == NULL);
        assert_se(streq(y, "piff"));

        p = mfree(p);
        assert_se(p = path_join(tmp, "foo"));
        assert_se(write_string_file(p, "knurz", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE) >= 0);

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) >= 0);
        assert_se(streq(x, "knurz"));
        assert_se(streq(y, "piff"));

        y = mfree(y);

        assert_se(read_credential_strings_many("foo", &x, "bar", &y) >= 0);
        assert_se(streq(x, "knurz"));
        assert_se(streq(y, "paff"));

        p = mfree(p);
        assert_se(p = path_join(tmp, "bazz"));
        assert_se(f = fopen(p, "w"));
        assert_se(fwrite("x\0y", 1, 3, f) == 3); /* embedded NUL byte should result in EBADMSG when reading back with read_credential_strings_many() */
        f = safe_fclose(f);

        assert_se(read_credential_strings_many("bazz", &x, "foo", &y) == -EBADMSG);
        assert_se(streq(x, "knurz"));
        assert_se(streq(y, "paff"));

        if (saved)
                assert_se(setenv("CREDENTIALS_DIRECTORY", saved, /* override= */ 1) >= 0);
        else
                assert_se(unsetenv("CREDENTIALS_DIRECTORY") >= 0);
}

TEST(credential_name_valid) {
        char buf[NAME_MAX+2];

        assert_se(!credential_name_valid(NULL));
        assert_se(!credential_name_valid(""));
        assert_se(!credential_name_valid("."));
        assert_se(!credential_name_valid(".."));
        assert_se(!credential_name_valid("foo/bar"));
        assert_se(credential_name_valid("foo"));

        memset(buf, 'x', sizeof(buf)-1);
        buf[sizeof(buf)-1] = 0;
        assert_se(!credential_name_valid(buf));

        buf[sizeof(buf)-2] = 0;
        assert_se(credential_name_valid(buf));
}

TEST(credential_glob_valid) {
        char buf[NAME_MAX+2];

        assert_se(!credential_glob_valid(NULL));
        assert_se(!credential_glob_valid(""));
        assert_se(!credential_glob_valid("."));
        assert_se(!credential_glob_valid(".."));
        assert_se(!credential_glob_valid("foo/bar"));
        assert_se(credential_glob_valid("foo"));
        assert_se(credential_glob_valid("foo*"));
        assert_se(credential_glob_valid("x*"));
        assert_se(credential_glob_valid("*"));
        assert_se(!credential_glob_valid("?"));
        assert_se(!credential_glob_valid("*a"));
        assert_se(!credential_glob_valid("a?"));
        assert_se(!credential_glob_valid("a[abc]"));
        assert_se(!credential_glob_valid("a[abc]"));

        memset(buf, 'x', sizeof(buf)-1);
        buf[sizeof(buf)-1] = 0;
        assert_se(!credential_glob_valid(buf));

        buf[sizeof(buf)-2] = 0;
        assert_se(credential_glob_valid(buf));

        buf[sizeof(buf)-2] = '*';
        assert_se(credential_glob_valid(buf));
}

static void test_encrypt_decrypt_with(sd_id128_t mode) {
        static const struct iovec plaintext = CONST_IOVEC_MAKE_STRING("this is a super secret string");
        int r;

        log_notice("Running encryption/decryption test with mode " SD_ID128_FORMAT_STR ".", SD_ID128_FORMAT_VAL(mode));

        _cleanup_(iovec_done) struct iovec encrypted = {};
        r = encrypt_credential_and_warn(
                        mode,
                        "foo",
                        /* timestamp= */ USEC_INFINITY,
                        /* not_after=*/ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_hash_pcr_mask= */ 0,
                        /* tpm2_pubkey_path= */ NULL,
                        /* tpm2_pubkey_pcr_mask= */ 0,
                        &plaintext,
                        CREDENTIAL_ALLOW_NULL,
                        &encrypted);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) {
                log_notice_errno(r, "Skipping test encryption mode " SD_ID128_FORMAT_STR ", because /etc/machine-id is not initialized.", SD_ID128_FORMAT_VAL(mode));
                return;
        }
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                log_notice_errno(r, "Skipping test encryption mode " SD_ID128_FORMAT_STR ", because encrypted credentials are not supported.", SD_ID128_FORMAT_VAL(mode));
                return;
        }

        assert_se(r >= 0);

        _cleanup_(iovec_done) struct iovec decrypted = {};
        r = decrypt_credential_and_warn(
                        "bar",
                        /* validate_timestamp= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_signature_path= */ NULL,
                        &encrypted,
                        CREDENTIAL_ALLOW_NULL,
                        &decrypted);
        assert_se(r == -EREMOTE); /* name didn't match */

        r = decrypt_credential_and_warn(
                        "foo",
                        /* validate_timestamp= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_signature_path= */ NULL,
                        &encrypted,
                        CREDENTIAL_ALLOW_NULL,
                        &decrypted);
        assert_se(r >= 0);

        assert_se(iovec_memcmp(&plaintext, &decrypted) == 0);
}

static bool try_tpm2(void) {
#if HAVE_TPM2
        _cleanup_(tpm2_context_unrefp) Tpm2Context *tpm2_context = NULL;
        int r;

        r = tpm2_context_new(/* device= */ NULL, &tpm2_context);
        if (r < 0)
                log_notice_errno(r, "Failed to create TPM2 context, assuming no TPM2 support or privileges: %m");

        return r >= 0;
#else
        return false;
#endif
}

TEST(credential_encrypt_decrypt) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_free_ char *j = NULL;

        test_encrypt_decrypt_with(CRED_AES256_GCM_BY_NULL);

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);
        j = path_join(d, "secret");
        assert_se(j);

        const char *e = getenv("SYSTEMD_CREDENTIAL_SECRET");
        _cleanup_free_ char *ec = NULL;

        if (e)
                assert_se(ec = strdup(e));

        assert_se(setenv("SYSTEMD_CREDENTIAL_SECRET", j, true) >= 0);

        test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST);

        if (try_tpm2()) {
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_TPM2_HMAC);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC);
        }

        if (ec)
                assert_se(setenv("SYSTEMD_CREDENTIAL_SECRET", ec, true) >= 0);

}

DEFINE_TEST_MAIN(LOG_INFO);
