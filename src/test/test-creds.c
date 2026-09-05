/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "creds-util.h"
#include "env-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "id128-util.h"
#include "iovec-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "tpm2-util.h"
#include "user-util.h"

TEST(read_credential_strings) {
        _cleanup_free_ char *x = NULL, *y = NULL, *saved = NULL, *p = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tmp = NULL;
        _cleanup_fclose_ FILE *f = NULL;

        const char *e = getenv("CREDENTIALS_DIRECTORY");
        if (e)
                ASSERT_NOT_NULL((saved = strdup(e)));

        ASSERT_OK_ZERO(read_credential_strings_many("foo", &x, "bar", &y));
        ASSERT_NULL(x);
        ASSERT_NULL(y);

        ASSERT_OK(mkdtemp_malloc(NULL, &tmp));

        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", tmp, /* override= */ true));

        ASSERT_OK_ZERO(read_credential_strings_many("foo", &x, "bar", &y));
        ASSERT_NULL(x);
        ASSERT_NULL(y);

        ASSERT_NOT_NULL((p = path_join(tmp, "bar")));
        ASSERT_OK(write_string_file(p, "piff", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK_ZERO(read_credential_strings_many("foo", &x, "bar", &y));
        ASSERT_NULL(x);
        ASSERT_STREQ(y, "piff");

        ASSERT_OK(write_string_file(p, "paff", WRITE_STRING_FILE_TRUNCATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK_ZERO(read_credential_strings_many("foo", &x, "bar", &y));
        ASSERT_NULL(x);
        ASSERT_STREQ(y, "paff");

        p = mfree(p);
        ASSERT_NOT_NULL((p = path_join(tmp, "foo")));
        ASSERT_OK(write_string_file(p, "knurz", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));

        ASSERT_OK(read_credential_strings_many("foo", &x, "bar", &y));
        ASSERT_STREQ(x, "knurz");
        ASSERT_STREQ(y, "paff");

        p = mfree(p);
        ASSERT_NOT_NULL((p = path_join(tmp, "bazz")));
        ASSERT_NOT_NULL((f = fopen(p, "w")));
        ASSERT_EQ(fwrite("x\0y", 1, 3, f), 3UL); /* embedded NUL byte should result in EBADMSG when reading back with read_credential_strings_many() */
        f = safe_fclose(f);

        y = mfree(y);

        ASSERT_ERROR(read_credential_strings_many("bazz", &x, "bar", &y), EBADMSG);
        ASSERT_STREQ(x, "knurz");
        ASSERT_STREQ(y, "paff");

        if (saved)
                ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", saved, /* override= */ 1));
        else
                ASSERT_OK_ERRNO(unsetenv("CREDENTIALS_DIRECTORY"));
}

TEST(read_credential_with_decryption) {
        _cleanup_(rm_rf_physical_and_freep) char *plain_dir = NULL, *encrypted_dir = NULL;
        _cleanup_free_ char *saved_plain = NULL, *saved_encrypted = NULL;
        _cleanup_free_ char *plain_path = NULL, *encrypted_path = NULL;
        _cleanup_(iovec_done_erase) struct iovec data = {};
        char marker = 0;
        void *missing = &marker;
        size_t missing_size = SIZE_MAX;

        ASSERT_OK(free_and_strdup(&saved_plain, getenv("CREDENTIALS_DIRECTORY")));
        ASSERT_OK(free_and_strdup(&saved_encrypted, getenv("ENCRYPTED_CREDENTIALS_DIRECTORY")));
        ASSERT_OK(mkdtemp_malloc(NULL, &plain_dir));
        ASSERT_OK(mkdtemp_malloc(NULL, &encrypted_dir));
        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", plain_dir, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("ENCRYPTED_CREDENTIALS_DIRECTORY", encrypted_dir, /* overwrite= */ true));

        ASSERT_OK_ZERO(read_credential_with_decryption("missing", &missing, &missing_size));
        ASSERT_NULL(missing);
        ASSERT_EQ(missing_size, 0U);

        ASSERT_NOT_NULL(encrypted_path = path_join(encrypted_dir, "foo"));
        ASSERT_OK(write_string_file(encrypted_path, "!", WRITE_STRING_FILE_CREATE));
        ASSERT_LT(read_credential_with_decryption("foo", &data.iov_base, &data.iov_len), 0);

        /* Plaintext takes precedence over the invalid encrypted credential and is not Base64-decoded. */
        ASSERT_NOT_NULL(plain_path = path_join(plain_dir, "foo"));
        ASSERT_OK(write_string_file(plain_path, "Zm9v",
                                    WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE));
        ASSERT_OK_EQ(read_credential_with_decryption("foo", &data.iov_base, &data.iov_len), 1);
        ASSERT_EQ(data.iov_len, STRLEN("Zm9v"));
        ASSERT_STREQ(data.iov_base, "Zm9v");

        ASSERT_OK(set_unset_env("CREDENTIALS_DIRECTORY", saved_plain, /* overwrite= */ true));
        ASSERT_OK(set_unset_env("ENCRYPTED_CREDENTIALS_DIRECTORY", saved_encrypted, /* overwrite= */ true));
}

TEST(read_credential_with_decryption_encrypted) {
        static const struct iovec plaintext = CONST_IOVEC_MAKE_STRING("foo\0bar\n");
        _cleanup_(rm_rf_physical_and_freep) char *plain_dir = NULL, *encrypted_dir = NULL;
        _cleanup_free_ char *saved_plain = NULL, *saved_encrypted = NULL, *saved_secret = NULL;
        _cleanup_free_ char *secret_path = NULL, *credential_path = NULL;
        _cleanup_(iovec_done_erase) struct iovec encrypted = {};
        int r;

        if (!HAVE_OPENSSL)
                return (void) log_tests_skipped("OpenSSL support is disabled");
        if (geteuid() != 0)
                return (void) log_tests_skipped("reading encrypted credentials directly requires root");

        r = sd_id128_get_machine(NULL);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return (void) log_tests_skipped("machine ID is not initialized");
        ASSERT_OK(r);

        ASSERT_OK(free_and_strdup(&saved_plain, getenv("CREDENTIALS_DIRECTORY")));
        ASSERT_OK(free_and_strdup(&saved_encrypted, getenv("ENCRYPTED_CREDENTIALS_DIRECTORY")));
        ASSERT_OK(free_and_strdup(&saved_secret, getenv("SYSTEMD_CREDENTIAL_SECRET")));
        ASSERT_OK(mkdtemp_malloc(NULL, &plain_dir));
        ASSERT_OK(mkdtemp_malloc(NULL, &encrypted_dir));
        ASSERT_NOT_NULL(secret_path = path_join(encrypted_dir, "secret"));
        ASSERT_NOT_NULL(credential_path = path_join(encrypted_dir, "foo"));
        ASSERT_OK_ERRNO(setenv("CREDENTIALS_DIRECTORY", plain_dir, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("ENCRYPTED_CREDENTIALS_DIRECTORY", encrypted_dir, /* overwrite= */ true));
        ASSERT_OK_ERRNO(setenv("SYSTEMD_CREDENTIAL_SECRET", secret_path, /* overwrite= */ true));

        ASSERT_OK(encrypt_credential_and_warn(
                        CRED_AES256_GCM_BY_HOST,
                        "foo",
                        /* timestamp= */ USEC_INFINITY,
                        /* not_after= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_hash_pcr_mask= */ 0,
                        /* tpm2_pubkey_path= */ NULL,
                        /* tpm2_pubkey_pcr_mask= */ 0,
                        /* uid= */ UID_INVALID,
                        &plaintext,
                        /* flags= */ 0,
                        &encrypted));

        /* Exercise both single-line Base64 and the line wrapping used by systemd-creds. */
        FOREACH_ELEMENT(line_break, ((const size_t[]) { SIZE_MAX, 79 })) {
                _cleanup_(erase_and_freep) char *encoded = NULL;
                _cleanup_(iovec_done_erase) struct iovec result = {};

                ASSERT_OK(base64mem_full(encrypted.iov_base, encrypted.iov_len, *line_break, &encoded));
                ASSERT_OK(write_string_file(credential_path, encoded,
                                            WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_TRUNCATE));
                ASSERT_OK_EQ(read_credential_with_decryption("foo", &result.iov_base, &result.iov_len), 1);
                ASSERT_TRUE(iovec_equal(&plaintext, &result));
        }

        ASSERT_OK(set_unset_env("CREDENTIALS_DIRECTORY", saved_plain, /* overwrite= */ true));
        ASSERT_OK(set_unset_env("ENCRYPTED_CREDENTIALS_DIRECTORY", saved_encrypted, /* overwrite= */ true));
        ASSERT_OK(set_unset_env("SYSTEMD_CREDENTIAL_SECRET", saved_secret, /* overwrite= */ true));
}

TEST(credential_name_valid) {
        char buf[NAME_MAX+2];

        ASSERT_FALSE(credential_name_valid(NULL));
        ASSERT_FALSE(credential_name_valid(""));
        ASSERT_FALSE(credential_name_valid("."));
        ASSERT_FALSE(credential_name_valid(".."));
        ASSERT_FALSE(credential_name_valid("foo/bar"));
        ASSERT_TRUE(credential_name_valid("foo"));

        memset(buf, 'x', sizeof(buf)-1);
        buf[sizeof(buf)-1] = 0;
        ASSERT_FALSE(credential_name_valid(buf));

        buf[sizeof(buf)-2] = 0;
        ASSERT_TRUE(credential_name_valid(buf));
}

TEST(credential_glob_valid) {
        char buf[NAME_MAX+2];

        ASSERT_FALSE(credential_glob_valid(NULL));
        ASSERT_FALSE(credential_glob_valid(""));
        ASSERT_FALSE(credential_glob_valid("."));
        ASSERT_FALSE(credential_glob_valid(".."));
        ASSERT_FALSE(credential_glob_valid("foo/bar"));
        ASSERT_TRUE(credential_glob_valid("foo"));
        ASSERT_TRUE(credential_glob_valid("foo*"));
        ASSERT_TRUE(credential_glob_valid("x*"));
        ASSERT_TRUE(credential_glob_valid("*"));
        ASSERT_FALSE(credential_glob_valid("?"));
        ASSERT_FALSE(credential_glob_valid("*a"));
        ASSERT_FALSE(credential_glob_valid("a?"));
        ASSERT_FALSE(credential_glob_valid("a[abc]"));
        ASSERT_FALSE(credential_glob_valid("a[abc]"));

        memset(buf, 'x', sizeof(buf)-1);
        buf[sizeof(buf)-1] = 0;
        ASSERT_FALSE(credential_glob_valid(buf));

        buf[sizeof(buf)-2] = 0;
        ASSERT_TRUE(credential_glob_valid(buf));

        buf[sizeof(buf)-2] = '*';
        ASSERT_TRUE(credential_glob_valid(buf));
}

static void test_encrypt_decrypt_with(sd_id128_t mode, uid_t uid) {
        static const struct iovec plaintext = CONST_IOVEC_MAKE_STRING("this is a super secret string");
        int r;

        if (uid_is_valid(uid))
                log_notice("Running encryption/decryption test with mode " SD_ID128_FORMAT_STR " for UID " UID_FMT ".", SD_ID128_FORMAT_VAL(mode), uid);
        else
                log_notice("Running encryption/decryption test with mode " SD_ID128_FORMAT_STR ".", SD_ID128_FORMAT_VAL(mode));

        _cleanup_(iovec_done) struct iovec encrypted = {};
        r = encrypt_credential_and_warn(
                        mode,
                        "foo",
                        /* timestamp= */ USEC_INFINITY,
                        /* not_after= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_hash_pcr_mask= */ 0,
                        /* tpm2_pubkey_path= */ NULL,
                        /* tpm2_pubkey_pcr_mask= */ 0,
                        uid,
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

        ASSERT_OK(r);

        _cleanup_(iovec_done) struct iovec decrypted = {};
        r = decrypt_credential_and_warn(
                        "bar",
                        /* validate_timestamp= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_signature_path= */ NULL,
                        uid,
                        &encrypted,
                        CREDENTIAL_ALLOW_NULL,
                        &decrypted);
        ASSERT_ERROR(r, EDESTADDRREQ); /* name didn't match */

        r = decrypt_credential_and_warn(
                        "foo",
                        /* validate_timestamp= */ USEC_INFINITY,
                        /* tpm2_device= */ NULL,
                        /* tpm2_signature_path= */ NULL,
                        uid,
                        &encrypted,
                        CREDENTIAL_ALLOW_NULL,
                        &decrypted);
        ASSERT_OK(r);

        ASSERT_TRUE(iovec_equal(&plaintext, &decrypted));
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

        log_set_max_level(LOG_DEBUG);

        test_encrypt_decrypt_with(CRED_AES256_GCM_BY_NULL, UID_INVALID);

        ASSERT_OK(mkdtemp_malloc(NULL, &d));
        j = path_join(d, "secret");
        ASSERT_NOT_NULL(j);

        const char *e = getenv("SYSTEMD_CREDENTIAL_SECRET");
        _cleanup_free_ char *ec = NULL;

        if (e)
                ASSERT_NOT_NULL((ec = strdup(e)));

        ASSERT_OK_ERRNO(setenv("SYSTEMD_CREDENTIAL_SECRET", j, true));

        test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST, UID_INVALID);
        test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_SCOPED, 0);

        if (try_tpm2()) {
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_TPM2_HMAC, UID_INVALID);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC, UID_INVALID);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED, 0);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_TPM2_HMAC_PINNED_SRK, UID_INVALID);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_PINNED_SRK, UID_INVALID);
                test_encrypt_decrypt_with(CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED_PINNED_SRK, 0);
        }

        if (ec)
                ASSERT_OK_ERRNO(setenv("SYSTEMD_CREDENTIAL_SECRET", ec, true));
}

TEST(credential_boot_policy) {

        /* String table round-trip */
        for (CredentialBootPolicy p = 0; p < _CRED_BOOT_POLICY_MAX; p++) {
                const char *s = credential_boot_policy_to_string(p);
                ASSERT_NOT_NULL(s);
                ASSERT_EQ(credential_boot_policy_from_string(s), p);
        }
        ASSERT_STREQ(credential_boot_policy_to_string(CRED_BOOT_TOFU), "tofu");
        ASSERT_TRUE(credential_boot_policy_from_string("bogus") < 0);

        /* Exhaustively check the accept decision against every (first_boot, have_tpm2, secure_boot) state */
        for (int first_boot = 0; first_boot < 2; first_boot++)
                for (int have_tpm2 = 0; have_tpm2 < 2; have_tpm2++)
                        for (int secure_boot = 0; secure_boot < 2; secure_boot++) {
                                /* strict never accepts a null key, off always does */
                                ASSERT_FALSE(credential_boot_policy_accepts_null(CRED_BOOT_STRICT, first_boot, have_tpm2, secure_boot));
                                ASSERT_TRUE(credential_boot_policy_accepts_null(CRED_BOOT_OFF, first_boot, have_tpm2, secure_boot));

                                /* tofu accepts when first boot, or no TPM2 */
                                ASSERT_EQ(credential_boot_policy_accepts_null(CRED_BOOT_TOFU, first_boot, have_tpm2, secure_boot),
                                          first_boot || !have_tpm2);

                                /* relaxed accepts when SecureBoot off, or no TPM2 */
                                ASSERT_EQ(credential_boot_policy_accepts_null(CRED_BOOT_RELAXED, first_boot, have_tpm2, secure_boot),
                                          !secure_boot || !have_tpm2);
                        }
}

TEST(mime_type_matches) {

        static const sd_id128_t tags[] = {
                CRED_AES256_GCM_BY_HOST,
                CRED_AES256_GCM_BY_HOST_SCOPED,
                CRED_AES256_GCM_BY_TPM2_HMAC,
                CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED,
                CRED_AES256_GCM_BY_TPM2_HMAC_PINNED_SRK,
                CRED_AES256_GCM_BY_TPM2_HMAC_WITH_PK_PINNED_SRK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_PINNED_SRK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_SCOPED_PINNED_SRK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_PINNED_SRK,
                CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC_WITH_PK_SCOPED_PINNED_SRK,
                CRED_AES256_GCM_BY_NULL,
        };

        /* Generates the right <match/> expressions for these credentials according to the shared mime-info spec */
        FOREACH_ELEMENT(t, tags) {
                _cleanup_free_ char *encoded = NULL;

                ASSERT_OK(base64mem(t, sizeof(sd_id128_t), &encoded));

                /* Validate that the size matches expectations for the 4/3 factor size increase (rounding up) */
                ASSERT_EQ(strlen(encoded), DIV_ROUND_UP((128U / 8U), 3U) * 4U);

                /* Cut off rounded string where the ID ends, but now round down to get rid of characters that might contain follow-up data */
                encoded[128 / 6] = 0;

                printf("<match type=\"string\" value=\"%s\" offset=\"0\"/>\n", encoded);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
