/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_VALGRIND_VALGRIND_H
#  include <valgrind/valgrind.h>
#endif

#include "hexdecoct.h"
#include "resolved-dns-dnssec-crypto.h"
#include "tests.h"

static void iovec_dump_c(const char *name, const struct iovec *iov) {
        assert(iovec_is_set(iov));

        printf("static const uint8_t %s[] = {", name);
        const uint8_t *buf = iov->iov_base;
        for (size_t i = 0; i < iov->iov_len; i++) {
                if (i % 8 == 0)
                        fputs("\n        ", stdout);
                else
                        putchar(' ');

                fputs("0x", stdout);
                putchar(hexchar((buf[i] & 0xf0) >> 4));
                putchar(hexchar((buf[i] & 0x0f) >> 0));
                putchar(',');
        }
        puts("\n};\n");
}

static void export_bn(const BIGNUM *x, struct iovec *ret) {
        assert(x);
        assert(ret);

        _cleanup_(iovec_done) struct iovec iov = {};
        ASSERT_OK(iovec_alloc(sym_BN_num_bytes(x), &iov));
        ASSERT_EQ(sym_BN_bn2bin(x, iov.iov_base), (int) iov.iov_len);

        *ret = TAKE_STRUCT(iov);
}

static const uint8_t test_signature_buf[] = {
        0xa6, 0x6c, 0x60, 0xec, 0x89, 0x90, 0x74, 0xba,
        0x9a, 0x6b, 0x7b, 0xbe, 0xd5, 0x46, 0xfb, 0x5c,
        0xa1, 0x80, 0x15, 0x4c, 0x98, 0x1e, 0xae, 0x13,
        0x41, 0xf1, 0xd3, 0x9e, 0xe6, 0x4f, 0x57, 0x47,
        0x4b, 0xef, 0x3e, 0xe3, 0xdf, 0xef, 0x5e, 0x2f,
        0x76, 0xb2, 0x4a, 0x65, 0x72, 0x81, 0x19, 0xd7,
        0x6e, 0x1c, 0xe7, 0xed, 0x4b, 0x36, 0xd1, 0x06,
        0xaa, 0x86, 0x05, 0xbe, 0x9c, 0x8b, 0x69, 0x80,
        0x30, 0x7f, 0x13, 0xb0, 0x6f, 0xc8, 0x53, 0x42,
        0x00, 0xe2, 0x9e, 0xc6, 0x64, 0xcf, 0x83, 0xac,
        0x83, 0x38, 0x9a, 0xe7, 0xdf, 0x4a, 0x80, 0x08,
        0x22, 0x74, 0x6c, 0x14, 0x20, 0xfe, 0x7d, 0x92,
        0x5f, 0x53, 0xa8, 0xb6, 0x59, 0xd5, 0xae, 0x08,
        0x11, 0x30, 0x0f, 0xf2, 0x5d, 0x3d, 0x69, 0xa6,
        0x94, 0xf5, 0xfa, 0x58, 0xe3, 0x70, 0x75, 0x5b,
        0x68, 0xb1, 0x47, 0x10, 0x72, 0xbf, 0x97, 0xc5,
        0x96, 0x97, 0x05, 0x9a, 0xd5, 0x36, 0xa5, 0x84,
        0x99, 0x4d, 0x0d, 0xe9, 0x47, 0xeb, 0xa8, 0xac,
        0x63, 0xad, 0x70, 0x0d, 0xc1, 0x45, 0xf2, 0x84,
        0x5f, 0x58, 0xcc, 0xcc, 0x77, 0xb4, 0x46, 0xc2,
        0x7e, 0x30, 0xb6, 0x35, 0x76, 0x8c, 0xe8, 0x27,
        0xa3, 0x86, 0x32, 0x29, 0xe7, 0x72, 0x5e, 0x41,
        0x1f, 0x5d, 0x81, 0x35, 0xe8, 0x46, 0x17, 0x55,
        0x51, 0xc8, 0x88, 0x9e, 0x72, 0x9a, 0x78, 0xc2,
        0xed, 0x3c, 0x32, 0x54, 0xd6, 0x46, 0x94, 0xe1,
        0x9c, 0xce, 0xc1, 0x49, 0x2c, 0x43, 0x53, 0x7b,
        0x7d, 0xe3, 0xc5, 0x7e, 0x76, 0x5b, 0x4b, 0xe0,
        0xac, 0x3a, 0xaf, 0xea, 0xfd, 0xc6, 0x62, 0x64,
        0x0c, 0x17, 0xb7, 0x37, 0x6c, 0x1a, 0x7d, 0x69,
        0xea, 0x84, 0x54, 0x1b, 0xd5, 0x0e, 0x9e, 0x76,
        0x0a, 0x12, 0xb7, 0x29, 0xb4, 0xd2, 0x61, 0xc4,
        0x38, 0xb6, 0xfc, 0x34, 0xd2, 0x20, 0xb0, 0x90,
};

static const uint8_t test_digest_buf[] = {
        0x64, 0xec, 0x88, 0xca, 0x00, 0xb2, 0x68, 0xe5,
        0xba, 0x1a, 0x35, 0x67, 0x8a, 0x1b, 0x53, 0x16,
        0xd2, 0x12, 0xf4, 0xf3, 0x66, 0xb2, 0x47, 0x72,
        0x32, 0x53, 0x4a, 0x8a, 0xec, 0xa3, 0x7f, 0x3c,
};

static const uint8_t test_exponent_buf[] = {
        0x01, 0x00, 0x01,
};

static const uint8_t test_modulus_buf[] = {
        0xa6, 0xf9, 0xcc, 0xed, 0x81, 0x49, 0xf0, 0x83,
        0xa7, 0xe5, 0x15, 0x93, 0xdd, 0x64, 0xa1, 0x66,
        0x40, 0xf9, 0x46, 0xd2, 0x3d, 0x16, 0xfb, 0x84,
        0x50, 0x53, 0x55, 0xba, 0x87, 0xcb, 0x15, 0xb8,
        0x98, 0xa4, 0xd2, 0xb4, 0xa6, 0xb4, 0x41, 0x2b,
        0xb4, 0x32, 0x0a, 0xc7, 0x8a, 0xe0, 0xa0, 0x2f,
        0x4e, 0xf7, 0x57, 0x44, 0xd3, 0x27, 0x94, 0x8a,
        0x10, 0x71, 0xc5, 0x3d, 0xa7, 0x25, 0xc2, 0x3f,
        0xdd, 0x1a, 0xa3, 0x05, 0x73, 0x41, 0xd8, 0x1c,
        0x99, 0xfd, 0x7f, 0x84, 0xe5, 0x09, 0xd2, 0x89,
        0x93, 0x61, 0xc6, 0xd6, 0xac, 0x6e, 0x9d, 0xe0,
        0xfb, 0x86, 0x81, 0x4a, 0x2f, 0x0a, 0xe8, 0x11,
        0xc8, 0x7f, 0x2b, 0x8b, 0x1b, 0xa3, 0x00, 0x15,
        0x25, 0xf0, 0x44, 0x39, 0xcd, 0x43, 0xbc, 0x19,
        0xad, 0xfb, 0xd3, 0xa7, 0x3f, 0x63, 0xc1, 0x78,
        0x0b, 0x69, 0x46, 0xc8, 0xe5, 0x6e, 0x15, 0x75,
        0x08, 0x8e, 0xc5, 0x67, 0xb7, 0x51, 0x61, 0x8a,
        0xb1, 0xff, 0x0a, 0xc5, 0x11, 0x30, 0x71, 0xca,
        0x88, 0x02, 0x3b, 0xfc, 0x40, 0x06, 0x11, 0x8a,
        0x0c, 0x0f, 0xb2, 0x7c, 0xf4, 0xd7, 0x07, 0xf4,
        0x85, 0xcd, 0xb7, 0x70, 0xcc, 0x5e, 0x21, 0xa0,
        0xcf, 0xb3, 0xe7, 0x47, 0x3e, 0xab, 0x20, 0x72,
        0xc3, 0xea, 0xcd, 0xfd, 0xb8, 0x50, 0x7c, 0xaa,
        0x2f, 0xd3, 0xf2, 0xc1, 0x99, 0xbc, 0x9c, 0x34,
        0xfd, 0x53, 0x26, 0x87, 0x35, 0x37, 0x78, 0xac,
        0x19, 0x13, 0x43, 0xb3, 0x80, 0x92, 0x7d, 0xeb,
        0xe2, 0x05, 0x62, 0xbf, 0x50, 0xde, 0x18, 0x17,
        0x74, 0xff, 0xa2, 0x5b, 0xfd, 0x14, 0xbf, 0xdd,
        0x21, 0xa6, 0xcb, 0xb9, 0x67, 0xce, 0x50, 0x06,
        0x91, 0x26, 0x71, 0x97, 0x5c, 0xf1, 0x81, 0x3b,
        0x68, 0xe8, 0xd9, 0xdf, 0xd3, 0xe3, 0xcc, 0x61,
        0xae, 0x73, 0x6c, 0xc8, 0x6c, 0x7b, 0x67, 0xd3,
};

static const struct iovec test_signature = IOVEC_MAKE(test_signature_buf, sizeof(test_signature_buf));
static const struct iovec test_digest = IOVEC_MAKE(test_digest_buf, sizeof(test_digest_buf));
static const struct iovec test_exponent = IOVEC_MAKE(test_exponent_buf, sizeof(test_exponent_buf));
static const struct iovec test_modulus = IOVEC_MAKE(test_modulus_buf, sizeof(test_modulus_buf));

TEST(generate_rsa_test_vectors) {
        /* This does not test anything but generates test vectors for dnssec_rsa_verify_raw().
         * This is skipped when we are running on valgrind or sanitizers, as it is extremely slow. */
#if HAVE_VALGRIND_VALGRIND_H
        if (RUNNING_ON_VALGRIND)
                return (void) log_tests_skipped("Running on valgrind");
#endif
#if HAS_FEATURE_ADDRESS_SANITIZER
        return (void) log_tests_skipped("Running on sanitizers");
#endif

        const struct iovec test_message = CONST_IOVEC_MAKE_STRING("Hello world");

        /* Generate a 2048-bit RSA key pair. */
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *kctx =
                ASSERT_NOT_NULL(sym_EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_keygen_init(kctx));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048));
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_generate(kctx, &pkey));

        /* Export public key parameters. */
        _cleanup_(BN_freep) BIGNUM *n = NULL, *e = NULL;
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e));
        _cleanup_(iovec_done) struct iovec modulus = {}, exponent = {};
        export_bn(n, &modulus);
        export_bn(e, &exponent);

        /* Calculate SHA-256 digest. */
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mctx = ASSERT_NOT_NULL(sym_EVP_MD_CTX_new());
        ASSERT_OK_POSITIVE(sym_EVP_DigestInit_ex(mctx, sym_EVP_sha256(), NULL));
        ASSERT_OK_POSITIVE(sym_EVP_DigestUpdate(mctx, test_message.iov_base, test_message.iov_len));
        struct iovec digest = IOVEC_ALLOCA(EVP_MAX_MD_SIZE);
        unsigned len;
        ASSERT_OK_POSITIVE(sym_EVP_DigestFinal_ex(mctx, digest.iov_base, &len));
        digest.iov_len = len;

        /* Sign the digest with RSA PKCS#1 v1.5. */
        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *sctx = ASSERT_PTR(sym_EVP_PKEY_CTX_new(pkey, NULL));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_sign_init(sctx));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING));
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_CTX_set_signature_md(sctx, sym_EVP_sha256()));
        size_t sz;
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_sign(sctx, NULL, &sz, digest.iov_base, digest.iov_len));
        struct iovec signature = IOVEC_ALLOCA(sz);
        ASSERT_OK_POSITIVE(sym_EVP_PKEY_sign(sctx, signature.iov_base, &signature.iov_len, digest.iov_base, digest.iov_len));

        iovec_dump_c("test_signature_buf", &signature);
        iovec_dump_c("test_digest_buf", &digest);
        iovec_dump_c("test_exponent_buf", &exponent);
        iovec_dump_c("test_modulus_buf", &modulus);
}

#define TEST_RSA_VERIFY(signature, digest, exponent, modulus, expected) \
        if (expected >= 0)                                              \
                ASSERT_OK_EQ(dnssec_rsa_verify_raw(                     \
                                             sym_EVP_sha256(),          \
                                             signature.iov_base, signature.iov_len, \
                                             digest.iov_base, digest.iov_len, \
                                             exponent.iov_base, exponent.iov_len, \
                                             modulus.iov_base, modulus.iov_len), \
                             expected);                                 \
        else                                                            \
                ASSERT_ERROR(dnssec_rsa_verify_raw(                     \
                                             sym_EVP_sha256(),          \
                                             signature.iov_base, signature.iov_len, \
                                             digest.iov_base, digest.iov_len, \
                                             exponent.iov_base, exponent.iov_len, \
                                             modulus.iov_base, modulus.iov_len), \
                             -expected);

TEST(dnssec_rsa_verify_raw) {
#if !defined(OPENSSL_NO_DEPRECATED_3_0)
        uint8_t *p;

        TEST_RSA_VERIFY(test_signature, test_digest, test_exponent, test_modulus, 1);

        _cleanup_(iovec_done) struct iovec bad_signature = {};
        ASSERT_NOT_NULL(iovec_memdup(&test_signature, &bad_signature));
        p = bad_signature.iov_base;
        p[0] ^= 0x01;
        TEST_RSA_VERIFY(bad_signature, test_digest, test_exponent, test_modulus, 0);

        p[0] ^= 0x01;
        bad_signature.iov_len -= 1;
        TEST_RSA_VERIFY(bad_signature, test_digest, test_exponent, test_modulus, -EINVAL);

        _cleanup_(iovec_done) struct iovec bad_digest = {};
        ASSERT_NOT_NULL(iovec_memdup(&test_digest, &bad_digest));
        p = bad_digest.iov_base;
        p[0] ^= 0x01;
        TEST_RSA_VERIFY(test_signature, bad_digest, test_exponent, test_modulus, 0);

        p[0] ^= 0x01;
        bad_digest.iov_len -= 1;
        TEST_RSA_VERIFY(test_signature, bad_digest, test_exponent, test_modulus, 0);

        _cleanup_(iovec_done) struct iovec bad_exponent = {};
        ASSERT_NOT_NULL(iovec_memdup(&test_exponent, &bad_exponent));
        p = bad_exponent.iov_base;
        p[0] ^= 0x01;
        TEST_RSA_VERIFY(test_signature, test_digest, bad_exponent, test_modulus, 0);

        p[0] ^= 0x01;
        bad_exponent.iov_len -= 1;
        TEST_RSA_VERIFY(test_signature, test_digest, bad_exponent, test_modulus, 0);

        _cleanup_(iovec_done) struct iovec bad_modulus = {};
        ASSERT_NOT_NULL(iovec_memdup(&test_modulus, &bad_modulus));
        p = bad_modulus.iov_base;
        p[0] ^= 0x01;
        TEST_RSA_VERIFY(test_signature, test_digest, test_exponent, bad_modulus, 0);

        p[0] ^= 0x01;
        p[bad_modulus.iov_len - 1] ^= 0x01;
        TEST_RSA_VERIFY(test_signature, test_digest, test_exponent, bad_modulus, 0);

        p[bad_modulus.iov_len - 1] ^= 0x01;
        bad_modulus.iov_len -= 1;
        TEST_RSA_VERIFY(test_signature, test_digest, test_exponent, bad_modulus, -EINVAL);
#else
        TEST_RSA_VERIFY(test_signature, test_digest, test_exponent, test_modulus, -EOPNOTSUPP);
#endif
}

static int intro(void) {
        if (DLOPEN_LIBCRYPTO(LOG_DEBUG, SD_ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED) < 0)
                return EXIT_TEST_SKIP;

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
