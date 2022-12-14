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
        test_tpm2_pcr_mask_from_string_one("7+application-support", 8388736, 0);
        test_tpm2_pcr_mask_from_string_one("8+boot-loader-code", 272, 0);
        test_tpm2_pcr_mask_from_string_one("6+boot-loader-code,44", 0, -EINVAL);
        test_tpm2_pcr_mask_from_string_one("7,shim-policy,4", 16528, 0);
        test_tpm2_pcr_mask_from_string_one("sysexts,shim-policy+kernel-boot", 26624, 0);
        test_tpm2_pcr_mask_from_string_one("sysexts,shim+kernel-boot", 0, -EINVAL);
        test_tpm2_pcr_mask_from_string_one("sysexts+17+23", 8527872, 0);
        test_tpm2_pcr_mask_from_string_one("debug+24", 0, -EINVAL);
}

TEST(pcr_index_from_string) {
        assert_se(pcr_index_from_string("platform-code") == 0);
        assert_se(pcr_index_from_string("0") == 0);
        assert_se(pcr_index_from_string("platform-config") == 1);
        assert_se(pcr_index_from_string("1") == 1);
        assert_se(pcr_index_from_string("external-code") == 2);
        assert_se(pcr_index_from_string("2") == 2);
        assert_se(pcr_index_from_string("external-config") == 3);
        assert_se(pcr_index_from_string("3") == 3);
        assert_se(pcr_index_from_string("boot-loader-code") == 4);
        assert_se(pcr_index_from_string("4") == 4);
        assert_se(pcr_index_from_string("boot-loader-config") == 5);
        assert_se(pcr_index_from_string("5") == 5);
        assert_se(pcr_index_from_string("secure-boot-policy") == 7);
        assert_se(pcr_index_from_string("7") == 7);
        assert_se(pcr_index_from_string("kernel-initrd") == 9);
        assert_se(pcr_index_from_string("9") == 9);
        assert_se(pcr_index_from_string("ima") == 10);
        assert_se(pcr_index_from_string("10") == 10);
        assert_se(pcr_index_from_string("kernel-boot") == 11);
        assert_se(pcr_index_from_string("11") == 11);
        assert_se(pcr_index_from_string("kernel-config") == 12);
        assert_se(pcr_index_from_string("12") == 12);
        assert_se(pcr_index_from_string("sysexts") == 13);
        assert_se(pcr_index_from_string("13") == 13);
        assert_se(pcr_index_from_string("shim-policy") == 14);
        assert_se(pcr_index_from_string("14") == 14);
        assert_se(pcr_index_from_string("system-identity") == 15);
        assert_se(pcr_index_from_string("15") == 15);
        assert_se(pcr_index_from_string("debug") == 16);
        assert_se(pcr_index_from_string("16") == 16);
        assert_se(pcr_index_from_string("application-support") == 23);
        assert_se(pcr_index_from_string("23") == 23);
        assert_se(pcr_index_from_string("hello") == -EINVAL);
        assert_se(pcr_index_from_string("8") == 8);
        assert_se(pcr_index_from_string("44") == -EINVAL);
        assert_se(pcr_index_from_string("-5") == -EINVAL);
        assert_se(pcr_index_from_string("24") == -EINVAL);
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

#if HAVE_TPM2

#define POISON(type)                                            \
        ({                                                      \
                type _p;                                        \
                memset(&_p, 0xaa, sizeof(_p));                  \
                _p;                                             \
        })
#define POISON_TPML POISON(TPML_PCR_SELECTION)
#define POISON_TPMS POISON(TPMS_PCR_SELECTION)
#define POISON_U32  POISON(uint32_t)

static void assert_tpms_pcr_selection_eq(TPMS_PCR_SELECTION *a, TPMS_PCR_SELECTION *b) {
        assert_se(a);
        assert_se(b);

        assert_se(a->hash == b->hash);
        assert_se(a->sizeofSelect == b->sizeofSelect);

        for (size_t i = 0; i < a->sizeofSelect; i++)
                assert_se(a->pcrSelect[i] == b->pcrSelect[i]);
}

static void assert_tpml_pcr_selection_eq(TPML_PCR_SELECTION *a, TPML_PCR_SELECTION *b) {
        assert_se(a);
        assert_se(b);

        assert_se(a->count == b->count);
        for (size_t i = 0; i < a->count; i++)
                assert_tpms_pcr_selection_eq(&a->pcrSelections[i], &b->pcrSelections[i]);
}

static void verify_tpms_pcr_selection(TPMS_PCR_SELECTION *s, uint32_t mask, TPMI_ALG_HASH hash) {
        assert_se(s->hash == hash);
        assert_se(s->sizeofSelect == 3);
        assert_se(s->pcrSelect[0] == (mask & 0xff));
        assert_se(s->pcrSelect[1] == ((mask >> 8) & 0xff));
        assert_se(s->pcrSelect[2] == ((mask >> 16) & 0xff));
        assert_se(s->pcrSelect[3] == 0);

        uint32_t m = POISON_U32;
        tpm2_tpms_pcr_selection_to_mask(s, &m);
        assert_se(m == mask);
}

static void verify_tpml_pcr_selection(TPML_PCR_SELECTION *l, TPMS_PCR_SELECTION s[], size_t count) {
        assert_se(l->count == count);
        for (size_t i = 0; i < count; i++) {
                assert_tpms_pcr_selection_eq(&s[i], &l->pcrSelections[i]);

                uint32_t mask = POISON_U32;
                TPMI_ALG_HASH hash = l->pcrSelections[i].hash;
                assert_se(tpm2_tpml_pcr_selection_to_mask(l, hash, &mask) == 0);
                verify_tpms_pcr_selection(&l->pcrSelections[i], mask, hash);
        }
}

static void _test_pcr_selection_mask_hash(uint32_t mask, TPMI_ALG_HASH hash) {
        TPMS_PCR_SELECTION s = POISON_TPMS;
        tpm2_tpms_pcr_selection_from_mask(mask, hash, &s);
        verify_tpms_pcr_selection(&s, mask, hash);

        TPML_PCR_SELECTION l = POISON_TPML;
        tpm2_tpml_pcr_selection_from_mask(mask, hash, &l);
        verify_tpml_pcr_selection(&l, &s, 1);
        verify_tpms_pcr_selection(&l.pcrSelections[0], mask, hash);

        uint32_t test_masks[] = {
                0x0, 0x1, 0x100, 0x10000, 0xf0f0f0, 0xaaaaaa, 0xffffff,
        };
        for (unsigned i = 0; i < ELEMENTSOF(test_masks); i++) {
                uint32_t test_mask = test_masks[i];

                TPMS_PCR_SELECTION a = POISON_TPMS, b = POISON_TPMS, test_s = POISON_TPMS;
                tpm2_tpms_pcr_selection_from_mask(test_mask, hash, &test_s);

                a = s;
                b = test_s;
                tpm2_tpms_pcr_selection_add(&a, &b);
                verify_tpms_pcr_selection(&a, UPDATE_FLAG(mask, test_mask, true), hash);
                verify_tpms_pcr_selection(&b, test_mask, hash);

                a = s;
                b = test_s;
                tpm2_tpms_pcr_selection_sub(&a, &b);
                verify_tpms_pcr_selection(&a, UPDATE_FLAG(mask, test_mask, false), hash);
                verify_tpms_pcr_selection(&b, test_mask, hash);

                a = s;
                b = test_s;
                tpm2_tpms_pcr_selection_move(&a, &b);
                verify_tpms_pcr_selection(&a, UPDATE_FLAG(mask, test_mask, true), hash);
                verify_tpms_pcr_selection(&b, 0, hash);
        }
}

TEST(tpms_pcr_selection_mask_and_hash) {
        TPMI_ALG_HASH HASH_ALGS[] = { TPM2_ALG_SHA1, TPM2_ALG_SHA256, };

        for (unsigned i = 0; i < ELEMENTSOF(HASH_ALGS); i++)
                for (uint32_t m2 = 0; m2 <= 0xffffff; m2 += 0x30000)
                        for (uint32_t m1 = 0; m1 <= 0xffff; m1 += 0x300)
                                for (uint32_t m0 = 0; m0 <= 0xff; m0 += 0x3)
                                        _test_pcr_selection_mask_hash(m0 | m1 | m2, HASH_ALGS[i]);
}

static void _test_tpms_sw(
                TPMI_ALG_HASH hash,
                uint32_t mask,
                const char *expected_str,
                size_t expected_weight) {

        TPMS_PCR_SELECTION s = POISON_TPMS;
        tpm2_tpms_pcr_selection_from_mask(mask, hash, &s);

        _cleanup_free_ char *tpms_str = tpm2_tpms_pcr_selection_to_string(&s);
        assert_se(streq(tpms_str, expected_str));

        assert_se(tpm2_tpms_pcr_selection_weight(&s) == expected_weight);
        assert_se(tpm2_tpms_pcr_selection_is_empty(&s) == (expected_weight == 0));
}

TEST(tpms_pcr_selection_string_and_weight) {
        TPMI_ALG_HASH sha1 = TPM2_ALG_SHA1, sha256 = TPM2_ALG_SHA256;

        _test_tpms_sw(sha1, 0, "sha1()", 0);
        _test_tpms_sw(sha1, 1, "sha1(0)", 1);
        _test_tpms_sw(sha1, 0xf, "sha1(0+1+2+3)", 4);
        _test_tpms_sw(sha1, 0x00ff00, "sha1(8+9+10+11+12+13+14+15)", 8);
        _test_tpms_sw(sha1, 0xffffff, "sha1(0+1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20+21+22+23)", 24);
        _test_tpms_sw(sha256, 0, "sha256()", 0);
        _test_tpms_sw(sha256, 1, "sha256(0)", 1);
        _test_tpms_sw(sha256, 7, "sha256(0+1+2)", 3);
        _test_tpms_sw(sha256, 0xf00000, "sha256(20+21+22+23)", 4);
        _test_tpms_sw(sha256, 0xffffff, "sha256(0+1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20+21+22+23)", 24);
}

static void _tpml_pcr_selection_add_tpms(TPMS_PCR_SELECTION s[], size_t count, TPML_PCR_SELECTION *ret) {
        for (size_t i = 0; i < count; i++)
                tpm2_tpml_pcr_selection_add_tpms_pcr_selection(ret, &s[i]);
}

static void _tpml_pcr_selection_sub_tpms(TPMS_PCR_SELECTION s[], size_t count, TPML_PCR_SELECTION *ret) {
        for (size_t i = 0; i < count; i++)
                tpm2_tpml_pcr_selection_sub_tpms_pcr_selection(ret, &s[i]);
}

static void _test_tpml_sw(
                TPMS_PCR_SELECTION s[],
                size_t count,
                size_t expected_count,
                const char *expected_str,
                size_t expected_weight) {

        TPML_PCR_SELECTION l = {};
        _tpml_pcr_selection_add_tpms(s, count, &l);
        assert_se(l.count == expected_count);

        _cleanup_free_ char *tpml_str = tpm2_tpml_pcr_selection_to_string(&l);
        assert_se(streq(tpml_str, expected_str));

        assert_se(tpm2_tpml_pcr_selection_weight(&l) == expected_weight);
        assert_se(tpm2_tpml_pcr_selection_is_empty(&l) == (expected_weight == 0));
}

TEST(tpml_pcr_selection_string_and_weight) {
        size_t size = 0xaa;
        TPMI_ALG_HASH sha1 = TPM2_ALG_SHA1,
                sha256 = TPM2_ALG_SHA256,
                sha384 = TPM2_ALG_SHA384,
                sha512 = TPM2_ALG_SHA512;
        TPMS_PCR_SELECTION s[4] = { POISON_TPMS, POISON_TPMS, POISON_TPMS, POISON_TPMS, };

        size = 0;
        tpm2_tpms_pcr_selection_from_mask(0x000002, sha1  , &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x0080f0, sha384, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x010100, sha512, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0xff0000, sha256, &s[size++]);
        _test_tpml_sw(s,
                      size,
                      /* expected_count= */ 4,
                      "[sha1(1),sha384(4+5+6+7+15),sha512(8+16),sha256(16+17+18+19+20+21+22+23)]",
                      /* expected_weight= */ 16);

        size = 0;
        tpm2_tpms_pcr_selection_from_mask(0x0403aa, sha512, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x0080f0, sha256, &s[size++]);
        _test_tpml_sw(s,
                      size,
                      /* expected_count= */ 2,
                      "[sha512(1+3+5+7+8+9+18),sha256(4+5+6+7+15)]",
                      /* expected_weight= */ 12);

        size = 0;
        /* Empty hashes should be ignored */
        tpm2_tpms_pcr_selection_from_mask(0x0300ce, sha384, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0xffffff, sha512, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x000000, sha1  , &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x330010, sha256, &s[size++]);
        _test_tpml_sw(s,
                      size,
                      /* expected_count= */ 3,
                      "[sha384(1+2+3+6+7+16+17),sha512(0+1+2+3+4+5+6+7+8+9+10+11+12+13+14+15+16+17+18+19+20+21+22+23),sha256(4+16+17+20+21)]",
                      /* expected_weight= */ 36);

        size = 0;
        /* Verify same-hash entries are properly combined. */
        tpm2_tpms_pcr_selection_from_mask(0x000001, sha1  , &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x000001, sha256, &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x000010, sha1  , &s[size++]);
        tpm2_tpms_pcr_selection_from_mask(0x000010, sha256, &s[size++]);
        _test_tpml_sw(s,
                      size,
                      /* expected_count= */ 2,
                      "[sha1(0+4),sha256(0+4)]",
                      /* expected_weight= */ 4);
}

/* Test tpml add/sub by changing the tpms individually */
static void _test_tpml_addsub_tpms(
                TPML_PCR_SELECTION *start,
                TPMS_PCR_SELECTION add[],
                size_t add_count,
                TPMS_PCR_SELECTION expected1[],
                size_t expected1_count,
                TPMS_PCR_SELECTION sub[],
                size_t sub_count,
                TPMS_PCR_SELECTION expected2[],
                size_t expected2_count) {

        TPML_PCR_SELECTION l = *start;

        _tpml_pcr_selection_add_tpms(add, add_count, &l);
        verify_tpml_pcr_selection(&l, expected1, expected1_count);

        _tpml_pcr_selection_sub_tpms(sub, sub_count, &l);
        verify_tpml_pcr_selection(&l, expected2, expected2_count);
}

/* Test tpml add/sub by creating new tpmls */
static void _test_tpml_addsub_tpml(
                TPML_PCR_SELECTION *start,
                TPMS_PCR_SELECTION add[],
                size_t add_count,
                TPMS_PCR_SELECTION expected1[],
                size_t expected1_count,
                TPMS_PCR_SELECTION sub[],
                size_t sub_count,
                TPMS_PCR_SELECTION expected2[],
                size_t expected2_count) {

        TPML_PCR_SELECTION l = {};
        tpm2_tpml_pcr_selection_add(&l, start);
        assert_tpml_pcr_selection_eq(&l, start);

        TPML_PCR_SELECTION addl = {};
        _tpml_pcr_selection_add_tpms(add, add_count, &addl);
        tpm2_tpml_pcr_selection_add(&l, &addl);

        TPML_PCR_SELECTION e1 = {};
        _tpml_pcr_selection_add_tpms(expected1, expected1_count, &e1);
        assert_tpml_pcr_selection_eq(&l, &e1);

        TPML_PCR_SELECTION subl = {};
        _tpml_pcr_selection_add_tpms(sub, sub_count, &subl);
        tpm2_tpml_pcr_selection_sub(&l, &subl);

        TPML_PCR_SELECTION e2 = {};
        _tpml_pcr_selection_add_tpms(expected2, expected2_count, &e2);
        assert_tpml_pcr_selection_eq(&l, &e2);
}

#define _test_tpml_addsub(...)                          \
        ({                                              \
                _test_tpml_addsub_tpms(__VA_ARGS__);    \
                _test_tpml_addsub_tpml(__VA_ARGS__);    \
        })

TEST(tpml_pcr_selection_add_sub) {
        size_t add_count = 0xaa, expected1_count = 0xaa, sub_count = 0xaa, expected2_count = 0xaa;
        TPMI_ALG_HASH sha1 = TPM2_ALG_SHA1,
                sha256 = TPM2_ALG_SHA256,
                sha384 = TPM2_ALG_SHA384,
                sha512 = TPM2_ALG_SHA512;
        TPML_PCR_SELECTION l = POISON_TPML;
        TPMS_PCR_SELECTION add[4] = { POISON_TPMS, POISON_TPMS, POISON_TPMS, POISON_TPMS, },
                sub[4] = { POISON_TPMS, POISON_TPMS, POISON_TPMS, POISON_TPMS, },
                expected1[4] = { POISON_TPMS, POISON_TPMS, POISON_TPMS, POISON_TPMS, },
                expected2[4] = { POISON_TPMS, POISON_TPMS, POISON_TPMS, POISON_TPMS, };

        l = (TPML_PCR_SELECTION){};
        add_count = 0;
        expected1_count = 0;
        sub_count = 0;
        expected2_count = 0;
        tpm2_tpms_pcr_selection_from_mask(0x010101, sha256, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x101010, sha256, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x111111, sha256, &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x000001, sha256, &sub[sub_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xff0000, sha512, &sub[sub_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x111110, sha256, &expected2[expected2_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &expected2[expected2_count++]);
        _test_tpml_addsub(&l,
                          add, add_count,
                          expected1, expected1_count,
                          sub, sub_count,
                          expected2, expected2_count);

        l = (TPML_PCR_SELECTION){
                .count = 1,
                .pcrSelections[0].hash = sha1,
                .pcrSelections[0].sizeofSelect = 3,
                .pcrSelections[0].pcrSelect[0] = 0xf0,
        };
        add_count = 0;
        expected1_count = 0;
        sub_count = 0;
        expected2_count = 0;
        tpm2_tpms_pcr_selection_from_mask(0xff0000, sha256, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xffff00, sha384, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xf00000, sha1  , &add[add_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xf000f0, sha1  , &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xff0000, sha256, &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xffff00, sha384, &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &expected1[expected1_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x00ffff, sha256, &sub[sub_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xf000f0, sha1  , &expected2[expected2_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xff0000, sha256, &expected2[expected2_count++]);
        tpm2_tpms_pcr_selection_from_mask(0xffff00, sha384, &expected2[expected2_count++]);
        tpm2_tpms_pcr_selection_from_mask(0x0000ff, sha512, &expected2[expected2_count++]);
        _test_tpml_addsub(&l,
                          add, add_count,
                          expected1, expected1_count,
                          sub, sub_count,
                          expected2, expected2_count);
}

/* this test includes TPM2 specific data structures */
TEST(tpm2_get_primary_template) {

        /*
         * Verify that if someone changes the template code, they know they're breaking things.
         * Templates MUST be changed in a backwards compatible way.
         *
         */
        static const TPM2B_PUBLIC templ[] = {
                /* index 0 RSA old */
                [0] = {
                        .publicArea = {
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
                        },
                },
                /* Index 1 ECC old */
                [TPM2_SRK_TEMPLATE_ECC] = {
                        .publicArea = {
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
                        },
                },
                /* index 2 RSA SRK */
                [TPM2_SRK_TEMPLATE_NEW_STYLE] = {
                        .publicArea = {
                                .type = TPM2_ALG_RSA,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_NODA,
                                .parameters.rsaDetail = {
                                        .symmetric = {
                                                .algorithm = TPM2_ALG_AES,
                                                .keyBits.aes = 128,
                                                .mode.aes = TPM2_ALG_CFB,
                                        },
                                        .scheme.scheme = TPM2_ALG_NULL,
                                        .keyBits = 2048,
                                },
                        },
                },
                /* Index 3 ECC SRK */
                [TPM2_SRK_TEMPLATE_NEW_STYLE | TPM2_SRK_TEMPLATE_ECC] = {
                        .publicArea = {
                                .type = TPM2_ALG_ECC,
                                .nameAlg = TPM2_ALG_SHA256,
                                .objectAttributes = TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_USERWITHAUTH|TPMA_OBJECT_NODA,
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
                        },
                },
        };

        assert_cc(ELEMENTSOF(templ) == _TPM2_SRK_TEMPLATE_MAX + 1);

        for (size_t i = 0; i < ELEMENTSOF(templ); i++) {
                /* the index counter lines up with the flags and the expected template received */
                const TPM2B_PUBLIC *got = tpm2_get_primary_template((Tpm2SRKTemplateFlags)i);
                assert_se(memcmp(&templ[i], got, sizeof(*got)) == 0);
        }
}

#define SHA256_T0 "0000000000000000000000000000000000000000000000000000000000000000"
#define SHA256_T1 "17b7703d9d00776310ba032e88c1a8c2a9c630ebdd799db622f6631530789175"
#define SHA256_T2 "12998c017066eb0d2a70b94e6ed3192985855ce390f321bbdb832022888bd251"
#define SHA256_T3 "c3a65887fedd3fb4f5d0047e906dff830bcbd1293160909eb4b05f485e7387ad"
#define SHA256_T4 "6491fb4bc08fc0b2ef47fc63db57e249917885e69d8c0d99667df83a59107a33"

#define DIGEST_COMPARE(d1, d2)                                          \
        ({                                                              \
                assert_se((d1).size == (d2).size);                      \
                assert_se(memcmp_safe((d1).buffer, (d2).buffer, (d1).size) == 0); \
        })

#define DIGEST_CHECK(digest, expect)                                    \
        ({                                                              \
                _cleanup_free_ char *_h = hexmem(digest.buffer, digest.size); \
                assert_se(_h != NULL);                                  \
                assert_se(streq(expect, _h));                           \
        })

#define DIGEST_INIT_SHA256(digest, hash)                                \
        ({                                                              \
                _cleanup_free_ void* _m = NULL;                         \
                size_t _s = 0;                                          \
                assert_se(strlen(hash) == SHA256_DIGEST_SIZE * 2);      \
                assert_se(strlen(hash) <= sizeof((digest).buffer) * 2); \
                assert_se(unhexmem(hash, strlen(hash), &_m, &_s) == 0); \
                assert_se(_s == SHA256_DIGEST_SIZE);                    \
                memcpy_safe((digest).buffer, _m, _s);                   \
                (digest).size = _s;                                     \
                DIGEST_CHECK(digest, hash);                             \
        })

TEST(digest_hash) {
        TPM2B_DIGEST d, d0, d1, d2, d3, d4;

        DIGEST_INIT_SHA256(d0, SHA256_T0);
        DIGEST_INIT_SHA256(d1, SHA256_T1);
        DIGEST_INIT_SHA256(d2, SHA256_T2);
        DIGEST_INIT_SHA256(d3, SHA256_T3);
        DIGEST_INIT_SHA256(d4, SHA256_T4);

        /* tpm2_digest_init, tpm2_digest_rehash */
        d = (TPM2B_DIGEST){ .size = 1, .buffer = { 2, }, };
        assert_se(tpm2_digest_init(TPM2_ALG_SHA256, &d) == 0);
        DIGEST_CHECK(d, SHA256_T0);
        assert_se(tpm2_digest_rehash(TPM2_ALG_SHA256, &d) == 0);
        DIGEST_CHECK(d, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");

        d = d1;
        assert_se(tpm2_digest_rehash(TPM2_ALG_SHA256, &d) == 0);
        DIGEST_CHECK(d, "ab55014b5ace12ba70c3acc887db571585a83539aad3633d252a710f268f405c");
        assert_se(tpm2_digest_init(TPM2_ALG_SHA256, &d) == 0);
        DIGEST_CHECK(d, SHA256_T0);

        /* tpm2_digest_init_digest, tpm2_digest_extend_digest */
        assert_se(tpm2_digest_init_digest(TPM2_ALG_SHA256, &d, &d2) == 0);
        DIGEST_CHECK(d, "56571a1be3fbeab18d215f549095915a004b5788ca0d535be668559129a76f25");
        assert_se(tpm2_digest_extend_digest(TPM2_ALG_SHA256, &d, &d2) == 0);
        DIGEST_CHECK(d, "99dedaee8f4d8d10a8be184399fde8740d5e17ff783ee5c288a4486e4ce3a1fe");

        /* tpm2_digest_init_digests, tpm2_digest_extend_digests */
        const TPM2B_DIGEST da1[] = { d2, d3, };
        assert_se(tpm2_digest_init_digests(TPM2_ALG_SHA256, &d, da1, ELEMENTSOF(da1)) == 0);
        DIGEST_CHECK(d, "525aa13ef9a61827778ec3acf16fbb23b65ae8770b8fb2684d3a33f9457dd6d8");
        assert_se(tpm2_digest_extend_digests(TPM2_ALG_SHA256, &d, da1, ELEMENTSOF(da1)) == 0);
        DIGEST_CHECK(d, "399ca2aa98963d1bd81a2b58a7e5cda24bba1be88fb4da9aa73d97706846566b");

        const TPM2B_DIGEST da2[] = { d3, d2, d0 };
        assert_se(tpm2_digest_init_digests(TPM2_ALG_SHA256, &d, da2, ELEMENTSOF(da2)) == 0);
        DIGEST_CHECK(d, "b26fd22db74d4cd896bff01c61aa498a575e4a553a7fb5a322a5fee36954313e");
        assert_se(tpm2_digest_extend_digests(TPM2_ALG_SHA256, &d, da2, ELEMENTSOF(da2)) == 0);
        DIGEST_CHECK(d, "091e79a5b09d4048df49a680f966f3ff67910afe185c3baf9704c9ca45bcf259");

        const TPM2B_DIGEST da3[] = { d4, d4, d4, d4, d3, d4, d4, d4, d4, };
        assert_se(tpm2_digest_init_digests(TPM2_ALG_SHA256, &d, da3, ELEMENTSOF(da3)) == 0);
        DIGEST_CHECK(d, "8eca947641b6002df79dfb571a7f78b7d0a61370a366f722386dfbe444d18830");
        assert_se(tpm2_digest_extend_digests(TPM2_ALG_SHA256, &d, da3, ELEMENTSOF(da3)) == 0);
        DIGEST_CHECK(d, "f9ba17bc0bbe8794e9bcbf112e4d59a11eb68fffbcd5516a746e4857829dff04");

        /* tpm2_digest_init_buffer, tpm2_digest_extend_buffer */
        const uint8_t b1[] = { 1, 2, 3, 4, };
        assert_se(tpm2_digest_init_buffer(TPM2_ALG_SHA256, &d, b1, ELEMENTSOF(b1)) == 0);
        DIGEST_CHECK(d, "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a");
        assert_se(tpm2_digest_extend_buffer(TPM2_ALG_SHA256, &d, b1, ELEMENTSOF(b1)) == 0);
        DIGEST_CHECK(d, "ff3bd307b287e9b29bb572f6ccfd19deb0106d0c4c3c5cfe8a1d03a396092ed4");

        const uint8_t *b2 = d2.buffer;
        assert_se(tpm2_digest_init_buffer(TPM2_ALG_SHA256, &d, b2, d2.size) == 0);
        DIGEST_CHECK(d, "56571a1be3fbeab18d215f549095915a004b5788ca0d535be668559129a76f25");
        assert_se(tpm2_digest_extend_buffer(TPM2_ALG_SHA256, &d, b2, d2.size) == 0);
        DIGEST_CHECK(d, "99dedaee8f4d8d10a8be184399fde8740d5e17ff783ee5c288a4486e4ce3a1fe");

        /* tpm2_digest_init_buffers, tpm2_digest_extend_buffers */
        const uint8_t *ba1[] = { b1, b2, d3.buffer };
        const size_t ba1len[] = { ELEMENTSOF(b1), d2.size, d3.size, };
        assert_se(tpm2_digest_init_buffers(TPM2_ALG_SHA256, &d, ba1, ba1len, ELEMENTSOF(ba1)) == 0);
        DIGEST_CHECK(d, "cd7bde4a047af976b6f1b282309976229be59f96a78aa186de32a1aee488ab09");
        assert_se(tpm2_digest_extend_buffers(TPM2_ALG_SHA256, &d, ba1, ba1len, ELEMENTSOF(ba1)) == 0);
        DIGEST_CHECK(d, "02ecb0628264235111e0053e271092981c8b15d59cd46617836bee3149a4ecb0");
}

static void TPM2B_PUBLIC_INIT(TPM2B_PUBLIC *public) {
        TPMT_PUBLIC tpmt = {
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

        const char *key = "9ec7341c52093ac40a1965a5df10432513c539adcf905e30577ab6ebc88ffe53cd08cef12ed9bec6125432f4fada3629b8b96d31b8f507aa35029188fe396da823fcb236027f7fbb01b0da3d87be7f999390449ced604bdf7e26c48657cc0671000f1147da195c3861c96642e54427cb7a11572e07567ec3fd6316978abc4bd92b27bb0a0e4958e599804eeb41d682b3b7fc1f960209f80a4fb8a1b64abfd96bf5d554e73cdd6ad1c8becb4fcf5e8f0c3e621d210e5e2f308f6520ad9a966779231b99f06c5989e5a23a9415c8808ab89ce81117632e2f8461cd4428bded40979236aeadafe8de3f51660a45e1dbc87694e6a36360201cca3ff9e7263e712727";
        _cleanup_free_ void *mem = NULL;
        size_t len = 0;
        assert_se(unhexmem(key, strlen(key), &mem, &len) == 0);
        assert_se(len <= sizeof(tpmt.unique.rsa.buffer));
        memcpy_safe(tpmt.unique.rsa.buffer, mem, len);
        tpmt.unique.rsa.size = len;

        public->publicArea = tpmt;
}

TEST(calculate_name) {
        TPM2B_PUBLIC public;
        TPM2B_NAME name;

        TPM2B_PUBLIC_INIT(&public);
        assert_se(tpm2_calculate_name(&public.publicArea, &name) == 0);
        assert_se(name.size == SHA256_DIGEST_SIZE + 2);

        const char *expect = "000be78f74a470dd92e979ca067cdb2293a35f075e8560b436bd2ccea5da21486a07";
        _cleanup_free_ char *h = hexmem(name.name, name.size);
        assert_se(h != NULL);
        assert_se(strlen(expect) == strlen(h));
        assert_se(streq(expect, h));
}

#endif /* HAVE_TPM2 */

DEFINE_TEST_MAIN(LOG_DEBUG);
