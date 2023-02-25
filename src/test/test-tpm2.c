/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "tpm2-util.h"
#include "tests.h"

static void test_tpm2_pcr_mask_from_string_one(const char *s, uint32_t mask, int ret) {
        uint32_t m;

        assert_se(tpm2_pcr_mask_from_string(s, &m) == ret);

        if (ret >= 0)
                assert_se(m == mask);
}

TEST(tpm2_mask_from_string) {
        test_tpm2_pcr_mask_from_string_one("", 0, 0);
        test_tpm2_pcr_mask_from_string_one("0", 1, 0);
        test_tpm2_pcr_mask_from_string_one("1", 2, 0);
        test_tpm2_pcr_mask_from_string_one("0,1", 3, 0);
        test_tpm2_pcr_mask_from_string_one("0+1", 3, 0);
        test_tpm2_pcr_mask_from_string_one("0-1", 0, -EINVAL);
        test_tpm2_pcr_mask_from_string_one("0,1,2", 7, 0);
        test_tpm2_pcr_mask_from_string_one("0+1+2", 7, 0);
        test_tpm2_pcr_mask_from_string_one("0+1,2", 7, 0);
        test_tpm2_pcr_mask_from_string_one("0,1+2", 7, 0);
        test_tpm2_pcr_mask_from_string_one("0,2", 5, 0);
        test_tpm2_pcr_mask_from_string_one("0+2", 5, 0);
        test_tpm2_pcr_mask_from_string_one("foo", 0, -EINVAL);
}

TEST(tpm2_util_pbkdf2_hmac_sha256) {

        /*
         * The test vectors from RFC 6070 [1] are for dkLen of 20 as it's SHA1
         * other RFCs I bumped into had various differing dkLen and iter counts,
         * so this was generated using Python's hmacmodule.
         *
         * 1. https://www.rfc-editor.org/rfc/rfc6070.html#page-2
         */
        static const struct {
                const uint8_t pass[256];
                size_t passlen;
                const uint8_t salt[256];
                size_t saltlen;
                uint8_t expected[SHA256_DIGEST_SIZE];
        } test_vectors[] = {
                { .pass={'f', 'o', 'o', 'p', 'a', 's', 's'},                                                                        .passlen=7,  .salt={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'}, .saltlen=16, .expected={0xCB, 0xEA, 0x27, 0x23, 0x9A, 0x65, 0x99, 0xF6, 0x8C, 0x26, 0x54, 0x80, 0x5C, 0x63, 0x61, 0xD2, 0x91, 0x0A, 0x60, 0x3F, 0xC2, 0xF5, 0xF0, 0xAB, 0x55, 0x8B, 0x46, 0x07, 0x60, 0x93, 0xAB, 0xCB} },
                { .pass={'f', 'o', 'o', 'p', 'a', 's', 's'},                                                                        .passlen=7,  .salt={0x00, 'h', 'f', 's', 'd', 'j', 'h', 'f', 'd', 'j', 'h', 'j', 'd', 'f', 's'},     .saltlen=15, .expected={0x2B, 0xDF, 0x52, 0x29, 0x48, 0x3F, 0x98, 0x25, 0x01, 0x19, 0xB4, 0x42, 0xBC, 0xA7, 0x38, 0x5D, 0xCD, 0x08, 0xBD, 0xDC, 0x33, 0xBF, 0x32, 0x5E, 0x31, 0x87, 0x54, 0xFF, 0x2C, 0x23, 0x68, 0xFF} },
                { .pass={'f', 'o', 'o', 'p', 'a', 's', 's'},                                                                        .passlen=7,  .salt={'m', 'y', 's', 'a', 0x00, 'l', 't'},                                             .saltlen=7,  .expected={0x7C, 0x24, 0xB4, 0x4D, 0x30, 0x11, 0x53, 0x24, 0x87, 0x56, 0x24, 0x10, 0xBA, 0x9F, 0xF2, 0x4E, 0xBB, 0xF5, 0x03, 0x56, 0x2B, 0xB1, 0xA1, 0x92, 0x8B, 0x5F, 0x32, 0x02, 0x23, 0x1F, 0x79, 0xE6} },
                { .pass={'p', 'a', 's', 's', 'w', 'i', 't', 'h', 'n', 'u', 'l', 'l', 0x00, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}, .passlen=21, .salt={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'}, .saltlen=16, .expected={0xE9, 0x53, 0xB7, 0x1D, 0xAB, 0xD1, 0xC1, 0xF3, 0xC4, 0x7F, 0x18, 0x96, 0xDD, 0xD7, 0x6B, 0xC6, 0x6A, 0xBD, 0xFB, 0x12, 0x7C, 0xF8, 0x68, 0xDC, 0x6E, 0xEF, 0x29, 0xCC, 0x1B, 0x30, 0x5B, 0x74} },
                { .pass={'p', 'a', 's', 's', 'w', 'i', 't', 'h', 'n', 'u', 'l', 'l', 0x00, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}, .passlen=21, .salt={0x00, 'h', 'f', 's', 'd', 'j', 'h', 'f', 'd', 'j', 'h', 'j', 'd', 'f', 's'},     .saltlen=15, .expected={0x51, 0xA3, 0x82, 0xA5, 0x2F, 0x48, 0x84, 0xB3, 0x02, 0x0D, 0xC2, 0x42, 0x9A, 0x8F, 0x86, 0xCC, 0x66, 0xFD, 0x65, 0x87, 0x89, 0x07, 0x2B, 0x07, 0x82, 0x42, 0xD6, 0x6D, 0x43, 0xB8, 0xFD, 0xCF} },
                { .pass={'p', 'a', 's', 's', 'w', 'i', 't', 'h', 'n', 'u', 'l', 'l', 0x00, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}, .passlen=21, .salt={'m', 'y', 's', 'a', 0x00, 'l', 't'},                                             .saltlen=7,  .expected={0xEC, 0xFB, 0x5D, 0x5F, 0xF6, 0xA6, 0xE0, 0x79, 0x50, 0x64, 0x36, 0x64, 0xA3, 0x9A, 0x5C, 0xF3, 0x7A, 0x87, 0x0B, 0x64, 0x51, 0x59, 0x75, 0x64, 0x8B, 0x78, 0x2B, 0x62, 0x8F, 0x68, 0xD9, 0xCC} },
                { .pass={0x00, 'p', 'a', 's', 's'},                                                                                 .passlen=5,  .salt={'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5'}, .saltlen=16, .expected={0x8A, 0x9A, 0x47, 0x9A, 0x91, 0x22, 0x2F, 0x56, 0x29, 0x4F, 0x26, 0x00, 0xE7, 0xB3, 0xEB, 0x63, 0x6D, 0x51, 0xF2, 0x60, 0x17, 0x08, 0x20, 0x70, 0x82, 0x8F, 0xA3, 0xD7, 0xBE, 0x2B, 0xD5, 0x5D} },
                { .pass={0x00, 'p', 'a', 's', 's'},                                                                                 .passlen=5,  .salt={0x00, 'h', 'f', 's', 'd', 'j', 'h', 'f', 'd', 'j', 'h', 'j', 'd', 'f', 's'},     .saltlen=15, .expected={0x72, 0x3A, 0xF5, 0xF7, 0xCD, 0x6C, 0x12, 0xDD, 0x53, 0x28, 0x46, 0x0C, 0x19, 0x0E, 0xF2, 0x91, 0xDE, 0xEA, 0xF9, 0x6F, 0x74, 0x32, 0x34, 0x3F, 0x84, 0xED, 0x8D, 0x2A, 0xDE, 0xC9, 0xC6, 0x34} },
                { .pass={0x00, 'p', 'a', 's', 's'},                                                                                 .passlen=5,  .salt={'m', 'y', 's', 'a', 0x00, 'l', 't'},                                             .saltlen=7,  .expected={0xE3, 0x07, 0x12, 0xBE, 0xEE, 0xF5, 0x5D, 0x18, 0x72, 0xF4, 0xCF, 0xF1, 0x20, 0x6B, 0xD6, 0x66, 0xCD, 0x7C, 0xE7, 0x4F, 0xC2, 0x16, 0x70, 0x5B, 0x9B, 0x2F, 0x7D, 0xE2, 0x3B, 0x42, 0x3A, 0x1B} },
        };

        uint8_t res[SHA256_DIGEST_SIZE];
        for(size_t i = 0; i < sizeof(test_vectors)/sizeof(test_vectors[0]); i++) {

                int rc = tpm2_util_pbkdf2_hmac_sha256(
                                test_vectors[i].pass,
                                test_vectors[i].passlen,
                                test_vectors[i].salt,
                                test_vectors[i].saltlen,
                                res);
                assert_se(rc == 0);
                assert_se(memcmp(test_vectors[i].expected, res, SHA256_DIGEST_SIZE) == 0);
        }
}

#ifdef HAVE_TPM2

static bool MARSHAL_DEBUG = 0;
static bool MARSHAL_SIZE_DEBUG = 0;
static bool MARSHAL_REALLOC_DEBUG = 0;
static bool UNMARSHAL_DEBUG = 0;

#define FILL_BUFFER(b, s, x)                                            \
        ({                                                              \
                _cleanup_free_ void *buf = NULL;                        \
                size_t size = 0;                                        \
                assert_se(unhexmem(x, strlen(x), &buf, &size) == 0);    \
                assert(size < sizeof(b));                               \
                memcpy_safe(b, buf, size);                              \
                s = size;                                               \
        })

#define test_tpm2_marshal(desc, src, expectedbuf, expectedsize)         \
        ({                                                              \
                _cleanup_free_ uint8_t *buf = malloc0(sizeof(src));     \
                size_t size = 0;                                        \
                assert_se(buf);                                         \
                assert_se(tpm2_marshal(desc, &src, buf, sizeof(src), &size) == 0); \
                if (MARSHAL_DEBUG) {                                    \
                        _cleanup_free_ char *__e = hexmem(expectedbuf, expectedsize); \
                        _cleanup_free_ char *__r = hexmem(buf, size);   \
                        assert_se(__e && __r);                          \
                        log_debug("marshal: expected %s", __e);         \
                        log_debug("marshal: result   %s", __r);         \
                }                                                       \
                assert_se(size == expectedsize);                        \
                assert_se(memcmp(buf, expectedbuf, expectedsize) == 0); \
        })

#define test_tpm2_marshal_size(desc, src, expectedsize)                 \
        ({                                                              \
                size_t size = 0;                                        \
                assert_se(tpm2_marshal_size(desc, &src, &size) == 0);   \
                if (MARSHAL_SIZE_DEBUG)                                 \
                        log_debug("marshal size: expected %lu result %lu", expectedsize, size); \
                assert_se(size == expectedsize);                        \
        })

#define test_tpm2_marshal_realloc(desc, src, expectedbuf, expectedsize) \
        ({                                                              \
                _cleanup_free_ uint8_t *buf = NULL;                     \
                size_t size = 0;                                        \
                assert_se(tpm2_marshal_realloc(desc, &src, &buf, &size) == 0); \
                assert_se(buf);                                         \
                if (MARSHAL_REALLOC_DEBUG) {                            \
                        _cleanup_free_ char *__e = hexmem(expectedbuf, expectedsize); \
                        _cleanup_free_ char *__r = hexmem(buf, size);   \
                        assert_se(__e && __r);                          \
                        log_debug("marshal realloc1: expected %s", __e); \
                        log_debug("marshal realloc1: result   %s", __r); \
                }                                                       \
                assert_se(size == expectedsize);                        \
                assert_se(memcmp(buf, expectedbuf, expectedsize) == 0); \
                assert_se(tpm2_marshal_realloc(desc, &src, &buf, &size) == 0); \
                assert_se(buf);                                         \
                uint8_t expectedbuf2[expectedsize * 2];                 \
                memcpy_safe(expectedbuf2, expectedbuf, expectedsize);   \
                memcpy_safe(&expectedbuf2[expectedsize], expectedbuf, expectedsize); \
                if (MARSHAL_REALLOC_DEBUG) {                            \
                        _cleanup_free_ char *__e = hexmem(expectedbuf2, expectedsize * 2); \
                        _cleanup_free_ char *__r = hexmem(buf, size);   \
                        assert_se(__e && __r);                          \
                        log_debug("marshal realloc2: expected %s", __e); \
                        log_debug("marshal realloc2: result   %s", __r); \
                }                                                       \
                assert_se(size == 2 * expectedsize);                    \
                assert_se(memcmp(buf, expectedbuf2, size) == 0);        \
        })

#define test_marshal(desc, src, expected)                               \
        ({                                                              \
                _cleanup_free_ void *expectedbuf = NULL;                \
                size_t expectedsize = 0;                                \
                assert_se(unhexmem(expected, strlen(expected), &expectedbuf, &expectedsize) == 0); \
                test_tpm2_marshal(desc, src, expectedbuf, expectedsize); \
                test_tpm2_marshal_size(desc, src, expectedsize);        \
                test_tpm2_marshal_realloc(desc, src, expectedbuf, expectedsize); \
        })

#define test_tpm2_unmarshal(desc, buf, size, expectedobj)               \
        ({                                                              \
                assert_se(buf);                                         \
                assert_se(size > 0);                                    \
                typeof(expectedobj) obj = {};                           \
                size_t offset = 0;                                      \
                assert_se(tpm2_unmarshal(desc, buf, size, &offset, &obj) == 0); \
                if (UNMARSHAL_DEBUG) {                                  \
                        _cleanup_free_ char *__e = hexmem((void*)&expectedobj, sizeof(expectedobj)); \
                        _cleanup_free_ char *__r = hexmem((void*)&obj, sizeof(obj)); \
                        assert_se(__e && __r);                          \
                        log_debug("expected %s", __e);                  \
                        log_debug("result   %s", __r);                  \
                }                                                       \
                assert_se(offset == size);                              \
                assert_se(memcmp(&obj, &expectedobj, sizeof(obj)) == 0); \
        })

#define test_unmarshal(desc, hex, expectedobj)                          \
        ({                                                              \
                _cleanup_free_ void *buf = NULL;                        \
                size_t size = 0;                                        \
                assert_se(unhexmem(hex, strlen(hex), &buf, &size) == 0); \
                test_tpm2_unmarshal(desc, buf, size, expectedobj);      \
        })

#define test_marshal_unmarshal(desc, obj, hex)                          \
        ({                                                              \
                test_marshal(desc, obj, hex);                           \
                test_unmarshal(desc, hex, obj);                         \
        })

#define test_marshal_unmarshal_set_size(desc, obj, hex)                 \
        ({                                                              \
                typeof(obj) o = (obj);                                  \
                o.size = sizeof(obj) - 2;                               \
                test_marshal(desc " (size field full)", o, hex);        \
                test_marshal_unmarshal(desc, obj, hex);                 \
        })

#define test_TPM2B_PUBLIC(desc, obj, hex) test_marshal_unmarshal_set_size(desc, obj, hex)

TEST_RET(marshal_unmarshal_tpm2b_public) {
        TPM2B_PUBLIC tpm2b_public = {};

        if (dlopen_tpm2() < 0)
                return log_tests_skipped("could not load tpm2 libraries");

        tpm2b_public.size = 0x1a;
        tpm2b_public.publicArea = (TPMT_PUBLIC){
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                .parameters.rsaDetail = {
                        .symmetric = {
                                .algorithm = TPM2_ALG_AES,
                                .keyBits.aes = 128,
                                .mode.aes = TPM2_ALG_CFB,
                        },
                        .scheme.scheme = TPM2_ALG_NULL,
                        .keyBits = 2048,
                },
        };
        test_TPM2B_PUBLIC("TPM2B_PUBLIC RSA, without unique", tpm2b_public,
                          "001a0001000b00030072000000060080004300100800000000000000");

        tpm2b_public.size = 0x2a;
        FILL_BUFFER(tpm2b_public.publicArea.unique.rsa.buffer,
                    tpm2b_public.publicArea.unique.rsa.size,
                    "40c68886f79677bc4da8f0d7dc5ed26e");
        test_TPM2B_PUBLIC("TPM2B_PUBLIC RSA, with unique", tpm2b_public,
                          "002a0001000b0003007200000006008000430010080000000000001040c68886f79677bc4da8f0d7dc5ed26e");

        tpm2b_public.size = 0x1a;
        tpm2b_public.publicArea = (TPMT_PUBLIC){
                .type = TPM2_ALG_ECC,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
                .parameters.eccDetail = {
                        .symmetric = {
                                .algorithm = TPM2_ALG_AES,
                                .keyBits.aes = 128,
                                .mode.aes = TPM2_ALG_CFB,
                        },
                        .scheme.scheme = TPM2_ALG_NULL,
                        .curveID = TPM2_ECC_NIST_P256,
                        .kdf.scheme = TPM2_ALG_NULL,
                },
        };
        test_TPM2B_PUBLIC("TPM2B_PUBLIC ECC, without unique", tpm2b_public,
                          "001a0023000b00030072000000060080004300100003001000000000");

        tpm2b_public.size = 0x2a;
        FILL_BUFFER(tpm2b_public.publicArea.unique.ecc.x.buffer,
                    tpm2b_public.publicArea.unique.ecc.x.size,
                    "57a531256e89e1ac9e4455a8c098f254");
        FILL_BUFFER(tpm2b_public.publicArea.unique.ecc.x.buffer,
                    tpm2b_public.publicArea.unique.ecc.x.size,
                    "0996faba7fc154a8dac28b6e0b05f0fe");
        test_TPM2B_PUBLIC("TPM2B_PUBLIC ECC, with unique", tpm2b_public,
                          "002a0023000b00030072000000060080004300100003001000100996faba7fc154a8dac28b6e0b05f0fe0000");

        return 0;
}

#define test_TPM2B_PRIVATE(...) test_marshal_unmarshal(__VA_ARGS__)

TEST_RET(marshal_unmarshal_tpm2b_private) {
        if (dlopen_tpm2() < 0)
                return log_tests_skipped("could not load tpm2 libraries");

        TPM2B_PRIVATE tpm2b_private = {};

        FILL_BUFFER(tpm2b_private.buffer, tpm2b_private.size,
                    "0020edcc19438b57fdcab1037a009f6b6cd8a486b70584796034bbd818f81b4f98e700108d32ede9484337a81313706a1bf907b05f33546af6ccdfbf6ee4ec2d37d6b329c0adbb02fe66000337d543569ee65352e4a74938e6814dd21eb30b5281f5107dda7dcf364ec8cf0e6ccf44846295e442e81b63d71c85e45e16beef2a41be8027cbd2bc332ade01ace63ffbb0e04a9df6c00fc2f813224ff988fe616c8a7ce500766c680d6e2740254d274f80197fc3cf1bd0fb9fe94c53be5c127bbc9f9b455cb4d2323c7e20ef431c73972a814b4d73159cac81d69a3575ada3");
        test_TPM2B_PRIVATE("TPM2B_PRIVATE RSA", tpm2b_private,
                           "00de0020edcc19438b57fdcab1037a009f6b6cd8a486b70584796034bbd818f81b4f98e700108d32ede9484337a81313706a1bf907b05f33546af6ccdfbf6ee4ec2d37d6b329c0adbb02fe66000337d543569ee65352e4a74938e6814dd21eb30b5281f5107dda7dcf364ec8cf0e6ccf44846295e442e81b63d71c85e45e16beef2a41be8027cbd2bc332ade01ace63ffbb0e04a9df6c00fc2f813224ff988fe616c8a7ce500766c680d6e2740254d274f80197fc3cf1bd0fb9fe94c53be5c127bbc9f9b455cb4d2323c7e20ef431c73972a814b4d73159cac81d69a3575ada3");


        return 0;
}

#endif /* HAVE_TPM2 */

DEFINE_TEST_MAIN(LOG_DEBUG);
