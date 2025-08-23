/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "hexdecoct.h"
#include "tests.h"
#include "tpm2-util.h"
#include "virt.h"

TEST(tpm2_pcr_index_from_string) {
        assert_se(tpm2_pcr_index_from_string("platform-code") == 0);
        assert_se(tpm2_pcr_index_from_string("0") == 0);
        assert_se(tpm2_pcr_index_from_string("platform-config") == 1);
        assert_se(tpm2_pcr_index_from_string("1") == 1);
        assert_se(tpm2_pcr_index_from_string("external-code") == 2);
        assert_se(tpm2_pcr_index_from_string("2") == 2);
        assert_se(tpm2_pcr_index_from_string("external-config") == 3);
        assert_se(tpm2_pcr_index_from_string("3") == 3);
        assert_se(tpm2_pcr_index_from_string("boot-loader-code") == 4);
        assert_se(tpm2_pcr_index_from_string("4") == 4);
        assert_se(tpm2_pcr_index_from_string("boot-loader-config") == 5);
        assert_se(tpm2_pcr_index_from_string("5") == 5);
        assert_se(tpm2_pcr_index_from_string("secure-boot-policy") == 7);
        assert_se(tpm2_pcr_index_from_string("7") == 7);
        assert_se(tpm2_pcr_index_from_string("kernel-initrd") == 9);
        assert_se(tpm2_pcr_index_from_string("9") == 9);
        assert_se(tpm2_pcr_index_from_string("ima") == 10);
        assert_se(tpm2_pcr_index_from_string("10") == 10);
        assert_se(tpm2_pcr_index_from_string("kernel-boot") == 11);
        assert_se(tpm2_pcr_index_from_string("11") == 11);
        assert_se(tpm2_pcr_index_from_string("kernel-config") == 12);
        assert_se(tpm2_pcr_index_from_string("12") == 12);
        assert_se(tpm2_pcr_index_from_string("sysexts") == 13);
        assert_se(tpm2_pcr_index_from_string("13") == 13);
        assert_se(tpm2_pcr_index_from_string("shim-policy") == 14);
        assert_se(tpm2_pcr_index_from_string("14") == 14);
        assert_se(tpm2_pcr_index_from_string("system-identity") == 15);
        assert_se(tpm2_pcr_index_from_string("15") == 15);
        assert_se(tpm2_pcr_index_from_string("debug") == 16);
        assert_se(tpm2_pcr_index_from_string("16") == 16);
        assert_se(tpm2_pcr_index_from_string("application-support") == 23);
        assert_se(tpm2_pcr_index_from_string("23") == 23);
        assert_se(tpm2_pcr_index_from_string("hello") == -EINVAL);
        assert_se(tpm2_pcr_index_from_string("8") == 8);
        assert_se(tpm2_pcr_index_from_string("44") == -EINVAL);
        assert_se(tpm2_pcr_index_from_string("-5") == -EINVAL);
        assert_se(tpm2_pcr_index_from_string("24") == -EINVAL);
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
        FOREACH_ELEMENT(vector, test_vectors) {
                int rc = tpm2_util_pbkdf2_hmac_sha256(
                                vector->pass,
                                vector->passlen,
                                vector->salt,
                                vector->saltlen,
                                res);
                assert_se(rc == 0);
                assert_se(memcmp(vector->expected, res, SHA256_DIGEST_SIZE) == 0);
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

        assert_se(tpm2_tpms_pcr_selection_to_mask(s) == mask);
}

static void verify_tpml_pcr_selection(TPML_PCR_SELECTION *l, TPMS_PCR_SELECTION s[], size_t count) {
        assert_se(l->count == count);
        for (size_t i = 0; i < count; i++) {
                assert_tpms_pcr_selection_eq(&s[i], &l->pcrSelections[i]);

                TPMI_ALG_HASH hash = l->pcrSelections[i].hash;
                verify_tpms_pcr_selection(&l->pcrSelections[i], tpm2_tpml_pcr_selection_to_mask(l, hash), hash);
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
        FOREACH_ELEMENT(i, test_masks) {
                uint32_t test_mask = *i;

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

        FOREACH_ELEMENT(hash, HASH_ALGS)
                for (uint32_t m2 = 0; m2 <= 0xffffff; m2 += 0x50000)
                        for (uint32_t m1 = 0; m1 <= 0xffff; m1 += 0x500)
                                for (uint32_t m0 = 0; m0 <= 0xff; m0 += 0x5)
                                        _test_pcr_selection_mask_hash(m0 | m1 | m2, *hash);
}

static void _test_tpms_sw(
                TPMI_ALG_HASH hash,
                uint32_t mask,
                const char *expected_str,
                size_t expected_weight) {

        TPMS_PCR_SELECTION s = POISON_TPMS;
        tpm2_tpms_pcr_selection_from_mask(mask, hash, &s);

        _cleanup_free_ char *tpms_str = tpm2_tpms_pcr_selection_to_string(&s);
        ASSERT_STREQ(tpms_str, expected_str);

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
        ASSERT_STREQ(tpml_str, expected_str);

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

static bool digest_check(const TPM2B_DIGEST *digest, const char *expect) {
        _cleanup_free_ char *h = NULL;

        assert_se(digest);
        assert_se(expect);

        h = hexmem(digest->buffer, digest->size);
        assert_se(h);

        return strcaseeq(expect, h);
}

static void digest_init(TPM2B_DIGEST *digest, const char *hash) {
        assert_se(strlen(hash) <= sizeof(digest->buffer) * 2);

        DEFINE_HEX_PTR(h, hash);

        /* Make sure the length matches a known hash algorithm */
        assert_se(IN_SET(h_len, TPM2_SHA1_DIGEST_SIZE, TPM2_SHA256_DIGEST_SIZE, TPM2_SHA384_DIGEST_SIZE, TPM2_SHA512_DIGEST_SIZE));

        *digest = TPM2B_DIGEST_MAKE(h, h_len);

        assert_se(digest_check(digest, hash));
}

TEST(digest_many) {
        TPM2B_DIGEST d, d0, d1, d2, d3, d4;

        digest_init(&d0, "0000000000000000000000000000000000000000000000000000000000000000");
        digest_init(&d1, "17b7703d9d00776310ba032e88c1a8c2a9c630ebdd799db622f6631530789175");
        digest_init(&d2, "12998c017066eb0d2a70b94e6ed3192985855ce390f321bbdb832022888bd251");
        digest_init(&d3, "c3a65887fedd3fb4f5d0047e906dff830bcbd1293160909eb4b05f485e7387ad");
        digest_init(&d4, "6491fb4bc08fc0b2ef47fc63db57e249917885e69d8c0d99667df83a59107a33");

        /* tpm2_digest_init, tpm2_digest_rehash */
        d = (TPM2B_DIGEST){ .size = 1, .buffer = { 2, }, };
        assert_se(tpm2_digest_init(TPM2_ALG_SHA256, &d) == 0);
        assert_se(digest_check(&d, "0000000000000000000000000000000000000000000000000000000000000000"));
        assert_se(tpm2_digest_rehash(TPM2_ALG_SHA256, &d) == 0);
        assert_se(digest_check(&d, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"));

        d = d1;
        assert_se(tpm2_digest_rehash(TPM2_ALG_SHA256, &d) == 0);
        assert_se(digest_check(&d, "ab55014b5ace12ba70c3acc887db571585a83539aad3633d252a710f268f405c"));
        assert_se(tpm2_digest_init(TPM2_ALG_SHA256, &d) == 0);
        assert_se(digest_check(&d, "0000000000000000000000000000000000000000000000000000000000000000"));

        /* tpm2_digest_many_digests */
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, &d2, 1, false) == 0);
        assert_se(digest_check(&d, "56571a1be3fbeab18d215f549095915a004b5788ca0d535be668559129a76f25"));
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, &d2, 1, true) == 0);
        assert_se(digest_check(&d, "99dedaee8f4d8d10a8be184399fde8740d5e17ff783ee5c288a4486e4ce3a1fe"));

        const TPM2B_DIGEST da1[] = { d2, d3, };
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da1, ELEMENTSOF(da1), false) == 0);
        assert_se(digest_check(&d, "525aa13ef9a61827778ec3acf16fbb23b65ae8770b8fb2684d3a33f9457dd6d8"));
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da1, ELEMENTSOF(da1), true) == 0);
        assert_se(digest_check(&d, "399ca2aa98963d1bd81a2b58a7e5cda24bba1be88fb4da9aa73d97706846566b"));

        const TPM2B_DIGEST da2[] = { d3, d2, d0 };
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da2, ELEMENTSOF(da2), false) == 0);
        assert_se(digest_check(&d, "b26fd22db74d4cd896bff01c61aa498a575e4a553a7fb5a322a5fee36954313e"));
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da2, ELEMENTSOF(da2), true) == 0);
        assert_se(digest_check(&d, "091e79a5b09d4048df49a680f966f3ff67910afe185c3baf9704c9ca45bcf259"));

        const TPM2B_DIGEST da3[] = { d4, d4, d4, d4, d3, d4, d4, d4, d4, };
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da3, ELEMENTSOF(da3), false) == 0);
        assert_se(digest_check(&d, "8eca947641b6002df79dfb571a7f78b7d0a61370a366f722386dfbe444d18830"));
        assert_se(tpm2_digest_many_digests(TPM2_ALG_SHA256, &d, da3, ELEMENTSOF(da3), true) == 0);
        assert_se(digest_check(&d, "f9ba17bc0bbe8794e9bcbf112e4d59a11eb68fffbcd5516a746e4857829dff04"));

        /* tpm2_digest_buffer */
        const uint8_t b1[] = { 1, 2, 3, 4, };
        assert_se(tpm2_digest_buffer(TPM2_ALG_SHA256, &d, b1, ELEMENTSOF(b1), false) == 0);
        assert_se(digest_check(&d, "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"));
        assert_se(tpm2_digest_buffer(TPM2_ALG_SHA256, &d, b1, ELEMENTSOF(b1), true) == 0);
        assert_se(digest_check(&d, "ff3bd307b287e9b29bb572f6ccfd19deb0106d0c4c3c5cfe8a1d03a396092ed4"));

        const void *b2 = d2.buffer;
        assert_se(tpm2_digest_buffer(TPM2_ALG_SHA256, &d, b2, d2.size, false) == 0);
        assert_se(digest_check(&d, "56571a1be3fbeab18d215f549095915a004b5788ca0d535be668559129a76f25"));
        assert_se(tpm2_digest_buffer(TPM2_ALG_SHA256, &d, b2, d2.size, true) == 0);
        assert_se(digest_check(&d, "99dedaee8f4d8d10a8be184399fde8740d5e17ff783ee5c288a4486e4ce3a1fe"));

        /* tpm2_digest_many */
        const struct iovec iov1[] = {
                IOVEC_MAKE((void*) b1, ELEMENTSOF(b1)),
                IOVEC_MAKE(d2.buffer, d2.size),
                IOVEC_MAKE(d3.buffer, d3.size),
        };
        assert_se(tpm2_digest_many(TPM2_ALG_SHA256, &d, iov1, ELEMENTSOF(iov1), false) == 0);
        assert_se(digest_check(&d, "cd7bde4a047af976b6f1b282309976229be59f96a78aa186de32a1aee488ab09"));
        assert_se(tpm2_digest_many(TPM2_ALG_SHA256, &d, iov1, ELEMENTSOF(iov1), true) == 0);
        assert_se(digest_check(&d, "02ecb0628264235111e0053e271092981c8b15d59cd46617836bee3149a4ecb0"));
}

static void check_parse_pcr_argument(
                const char *arg,
                const Tpm2PCRValue *prev_values,
                size_t n_prev_values,
                const Tpm2PCRValue *expected_values,
                size_t n_expected_values) {

        _cleanup_free_ Tpm2PCRValue *values = NULL;
        size_t n_values = 0;

        if (n_prev_values > 0) {
                assert_se(GREEDY_REALLOC_APPEND(values, n_values, prev_values, n_prev_values));
                assert_se(tpm2_parse_pcr_argument_append(arg, &values, &n_values) == 0);
        } else
                assert_se(tpm2_parse_pcr_argument(arg, &values, &n_values) == 0);

        assert_se(n_values == n_expected_values);
        for (size_t i = 0; i < n_values; i++) {
                const Tpm2PCRValue *v = &values[i], *e = &expected_values[i];
                //tpm2_log_debug_pcr_value(e, "Expected value");
                //tpm2_log_debug_pcr_value(v, "Actual value");

                assert_se(v->index == e->index);
                assert_se(v->hash == e->hash);
                assert_se(v->value.size == e->value.size);
                assert_se(memcmp(v->value.buffer, e->value.buffer, e->value.size) == 0);
        }

        size_t hash_count;
        assert_se(tpm2_pcr_values_hash_count(expected_values, n_expected_values, &hash_count) == 0);
        if (hash_count == 1) {
                uint32_t mask = UINT32_MAX, expected_mask = 0;

                if (n_prev_values > 0)
                        assert_se(tpm2_pcr_values_to_mask(prev_values, n_prev_values, prev_values[0].hash, &mask) == 0);

                assert_se(tpm2_pcr_values_to_mask(expected_values, n_expected_values, expected_values[0].hash, &expected_mask) == 0);

                _cleanup_free_ Tpm2PCRValue *arg_pcr_values = NULL;
                size_t n_arg_pcr_values = 0;
                assert_se(tpm2_parse_pcr_argument(arg, &arg_pcr_values, &n_arg_pcr_values) >= 0);
                uint32_t mask2 = UINT32_MAX;
                assert_se(tpm2_pcr_values_to_mask(arg_pcr_values, n_arg_pcr_values, /* hash= */ 0, &mask2) >= 0);

                assert_se((mask == UINT32_MAX ? mask2 : (mask|mask2)) == expected_mask);
        }

        size_t old_n_values = n_values;
        assert_se(tpm2_parse_pcr_argument_append("", &values, &n_values) == 0);
        assert_se(values);
        assert_se(n_values == old_n_values);
}

static void check_parse_pcr_argument_to_mask(const char *arg, int mask) {
        uint32_t m = 0;
        int r = tpm2_parse_pcr_argument_to_mask(arg, &m);

        if (mask < 0)
                assert_se(mask == r);
        else
                assert_se((uint32_t) mask == m);
}

TEST(parse_pcr_argument) {
        _cleanup_free_ Tpm2PCRValue *t0p = NULL;
        size_t n_t0p;
        assert_se(tpm2_parse_pcr_argument("", &t0p, &n_t0p) == 0);
        assert_se(n_t0p == 0);
        assert_se(tpm2_parse_pcr_argument_append("", &t0p, &n_t0p) == 0);
        assert_se(n_t0p == 0);
        uint32_t m0 = 0xf;
        assert_se(tpm2_parse_pcr_argument_to_mask("", &m0) == 0);
        assert_se(m0 == 0);
        assert_se(tpm2_parse_pcr_argument_to_mask("", &m0) == 0);
        assert_se(m0 == 0);

        Tpm2PCRValue t1[] = {
                TPM2_PCR_VALUE_MAKE(0, 0, {}),
                TPM2_PCR_VALUE_MAKE(4, 0, {}),
                TPM2_PCR_VALUE_MAKE(7, 0, {}),
                TPM2_PCR_VALUE_MAKE(11, 0, {}),
        };
        check_parse_pcr_argument("0,4,7,11", NULL, 0, t1, ELEMENTSOF(t1));
        check_parse_pcr_argument("11,4,7,0", NULL, 0, t1, ELEMENTSOF(t1));
        check_parse_pcr_argument("7,4,0,11", NULL, 0, t1, ELEMENTSOF(t1));
        check_parse_pcr_argument("11,7,4,0", NULL, 0, t1, ELEMENTSOF(t1));
        check_parse_pcr_argument("0+4+7+11", NULL, 0, t1, ELEMENTSOF(t1));
        check_parse_pcr_argument("0,4+7,11", NULL, 0, t1, ELEMENTSOF(t1));

        Tpm2PCRValue t2[] = {
                TPM2_PCR_VALUE_MAKE(0, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(4, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(7, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(11, TPM2_ALG_SHA1, {}),
        };
        check_parse_pcr_argument("0:sha1,4,7,11", NULL, 0, t2, ELEMENTSOF(t2));
        check_parse_pcr_argument("11,4,7,0:sha1", NULL, 0, t2, ELEMENTSOF(t2));
        check_parse_pcr_argument("7,4:sha1,0,11", NULL, 0, t2, ELEMENTSOF(t2));
        check_parse_pcr_argument("0:sha1,4:sha1,7:sha1,11:sha1", NULL, 0, t2, ELEMENTSOF(t2));
        check_parse_pcr_argument("0:sha1+4:sha1,11:sha1+7:sha1", NULL, 0, t2, ELEMENTSOF(t2));

        Tpm2PCRValue t3[] = {
                TPM2_PCR_VALUE_MAKE(0, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(1, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(2, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(3, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(4, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(7, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(11, TPM2_ALG_SHA1, {}),
                TPM2_PCR_VALUE_MAKE(12, TPM2_ALG_SHA1, {}),
        };
        check_parse_pcr_argument("1,2,3,12", t2, ELEMENTSOF(t2), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("12,2,3,1", t2, ELEMENTSOF(t2), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1,2,3,12:sha1", t1, ELEMENTSOF(t1), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1,2,3,12:sha1", t2, ELEMENTSOF(t2), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1:sha1,2,3,12", t1, ELEMENTSOF(t1), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1:sha1,2,3,12", t2, ELEMENTSOF(t2), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1:sha1,2:sha1,3:sha1,12:sha1", t1, ELEMENTSOF(t1), t3, ELEMENTSOF(t3));
        check_parse_pcr_argument("1:sha1,2:sha1,3:sha1,12:sha1", t2, ELEMENTSOF(t2), t3, ELEMENTSOF(t3));

        TPM2B_DIGEST d4;
        digest_init(&d4, "FCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2");
        Tpm2PCRValue t4[] = {
                TPM2_PCR_VALUE_MAKE(0, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(1, TPM2_ALG_SHA256, d4),
                TPM2_PCR_VALUE_MAKE(2, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(3, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(4, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(7, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(11, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(12, TPM2_ALG_SHA256, {}),
        };
        check_parse_pcr_argument("1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,2,3,12", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("12,2,3,1:sha256=FCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("12,2,3,1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,2,3,12:SHA256", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,2,3,12", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("1:sha256=FCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,2:sha256,3:sha256,12:sha256", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));
        check_parse_pcr_argument("1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,2:sha256,3:sha256,12:sha256", t1, ELEMENTSOF(t1), t4, ELEMENTSOF(t4));

        TPM2B_DIGEST d5;
        digest_init(&d5, "0F21EADB7F27377668E3C8069BE88D116491FBEE");
        Tpm2PCRValue t5[] = {
                TPM2_PCR_VALUE_MAKE(1, TPM2_ALG_SHA1, d5),
                TPM2_PCR_VALUE_MAKE(0, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(1, TPM2_ALG_SHA256, d4),
                TPM2_PCR_VALUE_MAKE(2, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(3, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(4, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(7, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(11, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(12, TPM2_ALG_SHA256, {}),
                TPM2_PCR_VALUE_MAKE(5, TPM2_ALG_SHA384, {}),
                TPM2_PCR_VALUE_MAKE(6, TPM2_ALG_SHA512, {}),
        };
        check_parse_pcr_argument("0,1:sha256=0xFCE7F1083082B16CFE2B085DD7858BB11A37C09B78E36C79E5A2FD529353C4E2,1:sha1=0F21EADB7F27377668E3C8069BE88D116491FBEE,2,3,4,7,11,12,5:sha384,6:sha512", NULL, 0, t5, ELEMENTSOF(t5));
        check_parse_pcr_argument("1:sha1=0F21EADB7F27377668E3C8069BE88D116491FBEE,6:sha512,5:sha384", t4, ELEMENTSOF(t4), t5, ELEMENTSOF(t5));

        Tpm2PCRValue *v = NULL;
        size_t n_v = 0;
        assert_se(tpm2_parse_pcr_argument("1,100", &v, &n_v) < 0);
        assert_se(tpm2_parse_pcr_argument("1,2=123456abc", &v, &n_v) < 0);
        assert_se(tpm2_parse_pcr_argument("1,2:invalid", &v, &n_v) < 0);
        assert_se(tpm2_parse_pcr_argument("1:sha1=invalid", &v, &n_v) < 0);
        ASSERT_NULL(v);
        assert_se(n_v == 0);

        check_parse_pcr_argument_to_mask("", 0x0);
        check_parse_pcr_argument_to_mask("0", 0x1);
        check_parse_pcr_argument_to_mask("1", 0x2);
        check_parse_pcr_argument_to_mask("0,1", 0x3);
        check_parse_pcr_argument_to_mask("0+1", 0x3);
        check_parse_pcr_argument_to_mask("0-1", -EINVAL);
        check_parse_pcr_argument_to_mask("foo", -EINVAL);
        check_parse_pcr_argument_to_mask("0,1,2", 0x7);
        check_parse_pcr_argument_to_mask("0+1+2", 0x7);
        check_parse_pcr_argument_to_mask("0+1,2", 0x7);
        check_parse_pcr_argument_to_mask("0,1+2", 0x7);
        check_parse_pcr_argument_to_mask("0,2", 0x5);
        check_parse_pcr_argument_to_mask("0+2", 0x5);
        check_parse_pcr_argument_to_mask("7+application-support", 0x800080);
        check_parse_pcr_argument_to_mask("8+boot-loader-code", 0x110);
        check_parse_pcr_argument_to_mask("7,shim-policy,4", 0x4090);
        check_parse_pcr_argument_to_mask("sysexts,shim-policy+kernel-boot", 0x6800);
        check_parse_pcr_argument_to_mask("sysexts,shim+kernel-boot", -EINVAL);
        check_parse_pcr_argument_to_mask("sysexts+17+23", 0x822000);
        check_parse_pcr_argument_to_mask("6+boot-loader-code,44", -EINVAL);
        check_parse_pcr_argument_to_mask("debug+24", -EINVAL);
        check_parse_pcr_argument_to_mask("5:sha1=f013d66c7f6817d08b7eb2a93e6d0440c1f3e7f8", -EINVAL);
        check_parse_pcr_argument_to_mask("0:sha256=f013d66c7f6817d08b7eb2a93e6d0440c1f3e7f8", -EINVAL);
        check_parse_pcr_argument_to_mask("5:sha1=f013d66c7f6817d08b7eb2a93e6d0440c1f3e7f8,3", -EINVAL);
        check_parse_pcr_argument_to_mask("3,0:sha256=f013d66c7f6817d08b7eb2a93e6d0440c1f3e7f8", -EINVAL);
}

static const TPMT_PUBLIC test_rsa_template = {
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

static const TPMT_PUBLIC test_ecc_template = {
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

static const TPMT_PUBLIC *test_templates[] = {
        &test_rsa_template,
        &test_ecc_template,
};

static void tpm2b_public_rsa_init(TPM2B_PUBLIC *public, const char *rsa_n) {
        TPMT_PUBLIC tpmt = test_rsa_template;

        DEFINE_HEX_PTR(key, rsa_n);
        tpmt.unique.rsa = TPM2B_PUBLIC_KEY_RSA_MAKE(key, key_len);

        public->size = sizeof(tpmt);
        public->publicArea = tpmt;
}

static void tpm2b_public_ecc_init(TPM2B_PUBLIC *public, TPMI_ECC_CURVE curve, const char *x, const char *y) {
        TPMT_PUBLIC tpmt = test_ecc_template;
        tpmt.parameters.eccDetail.curveID = curve;

        DEFINE_HEX_PTR(buf_x, x);
        tpmt.unique.ecc.x = TPM2B_ECC_PARAMETER_MAKE(buf_x, buf_x_len);

        DEFINE_HEX_PTR(buf_y, y);
        tpmt.unique.ecc.y = TPM2B_ECC_PARAMETER_MAKE(buf_y, buf_y_len);

        public->size = sizeof(tpmt);
        public->publicArea = tpmt;
}

#if HAVE_OPENSSL
TEST(tpm2b_public_to_openssl_pkey) {
        DEFINE_HEX_PTR(msg, "edc64c6523778961fe9ba03ab7d624b27ca1dd5b01e7734cc6c891d50db04269");
        TPM2B_PUBLIC public;

        /* RSA */
        tpm2b_public_rsa_init(&public, "d71cff5bba2173f0434a389171048e7da8cf8409b892c62946481cc383089bc754324620967fea3d00a02a717cdda4bfe1525ad957d294b88434e0a3933e86fb40f234e4935fd2ba27eb1d21da87efa466b74eb4ad18d26059904643441cf402ee933d138a2151f40459c49d87fef59e2cb822768b2d8689a9b58f82bf9a37e70693f2b2d40dfa388d365c1b1f029a14c4fc8dadb68978ef377d20ff2ca24e7078464c705eab42f531557c9c6dc0df66b506d0c26ef604f8110c64867099267453c71871e7ed22505a09daf102afc34355209ca7680eccc0ed368d148f402fa58cbb6c9d52351f535f09e4e24ad805e149f130edaa2f5e7efed3a4d2d03adb85");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_rsa = NULL;
        assert_se(tpm2_tpm2b_public_to_openssl_pkey(&public, &pkey_rsa) >= 0);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx_rsa = EVP_PKEY_CTX_new((EVP_PKEY*) pkey_rsa, NULL);
        assert_se(ctx_rsa);
        assert_se(EVP_PKEY_verify_init(ctx_rsa) == 1);
        assert_se(EVP_PKEY_CTX_set_signature_md(ctx_rsa, EVP_sha256()) > 0);

        DEFINE_HEX_PTR(sig_rsa, "9f70a9e68911be3ec464cae91126328307bf355872127e042d6c61e0a80982872c151033bcf727abfae5fc9500c923120011e7ef4aa5fc690a59a034697b6022c141b4b209e2df6f4b282288cd9181073fbe7158ce113c79d87623423c1f3996ff931e59cc91db74f8e8656215b1436fc93ddec0f1f8fa8510826e674b250f047e6cba94c95ff98072a286baca94646b577974a1e00d56c21944e38960d8ee90511a2f938e5cf1ac7b7cc7ff8e3ac001d321254d3e4f988b90e9f6f873c26ecd0a12a626b3474833cdbb9e9f793238f6c97ee5b75a1a89bb7a7858d34ecfa6d34ac58d95085e6c4fbbebd47a4364be2725c2c6b3fa15d916f3c0b62a66fe76ae");
        assert_se(EVP_PKEY_verify(ctx_rsa, sig_rsa, sig_rsa_len, (unsigned char*) msg, msg_len) == 1);

        /* ECC */
        tpm2b_public_ecc_init(&public, TPM2_ECC_NIST_P256, "6fc0ecf3645c673ab7e86d1ec5b315afb950257c5f68ab23296160006711fac2", "8dd2ef7a2c9ecede91493ba98c8fb3f893aff325c6a1e0f752c657b2d6ca1413");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_ecc = NULL;
        assert_se(tpm2_tpm2b_public_to_openssl_pkey(&public, &pkey_ecc) >= 0);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx_ecc = EVP_PKEY_CTX_new((EVP_PKEY*) pkey_ecc, NULL);
        assert_se(ctx_ecc);
        assert_se(EVP_PKEY_verify_init(ctx_ecc) == 1);

        DEFINE_HEX_PTR(sig_ecc, "304602210092447ac0b5b32e90923f79bb4aba864b9c546a9900cf193a83243d35d189a2110221009a8b4df1dfa85e225eff9c606694d4d205a7a3968c9552f50bc2790209a90001");
        assert_se(EVP_PKEY_verify(ctx_ecc, sig_ecc, sig_ecc_len, (unsigned char*) msg, msg_len) == 1);
}

static void get_tpm2b_public_from_pem(const void *pem, size_t pem_size, TPM2B_PUBLIC *ret) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        TPM2B_PUBLIC p1 = {}, p2 = {};

        assert(pem);
        assert(ret);

        assert_se(openssl_pubkey_from_pem(pem, pem_size, &pkey) >= 0);
        assert_se(tpm2_tpm2b_public_from_openssl_pkey(pkey, &p1) >= 0);
        assert_se(tpm2_tpm2b_public_from_pem(pem, pem_size, &p2) >= 0);
        assert_se(memcmp_nn(&p1, sizeof(p1), &p2, sizeof(p2)) == 0);

        *ret = p1;
}

static void check_tpm2b_public_fingerprint(const TPM2B_PUBLIC *public, const char *hexfp) {
        DEFINE_HEX_PTR(expected, hexfp);
        _cleanup_free_ void *fp = NULL;
        size_t fp_size;

        assert_se(tpm2_tpm2b_public_to_fingerprint(public, &fp, &fp_size) >= 0);
        assert_se(memcmp_nn(fp, fp_size, expected, expected_len) == 0);
}

static void check_tpm2b_public_name(const TPM2B_PUBLIC *public, const char *hexname) {
        DEFINE_HEX_PTR(expected, hexname);
        TPM2B_NAME name = {};

        assert_se(tpm2_calculate_pubkey_name(&public->publicArea, &name) >= 0);
        assert_se(memcmp_nn(name.name, name.size, expected, expected_len) == 0);
}

static void check_tpm2b_public_from_ecc_pem(const char *pem, const char *hexx, const char *hexy, const char *hexfp, const char *hexname) {
        TPM2B_PUBLIC public = {};
        TPMT_PUBLIC *p = &public.publicArea;

        DEFINE_HEX_PTR(key, pem);
        get_tpm2b_public_from_pem(key, key_len, &public);

        assert_se(p->type == TPM2_ALG_ECC);
        assert_se(p->parameters.eccDetail.curveID == TPM2_ECC_NIST_P256);

        DEFINE_HEX_PTR(expected_x, hexx);
        assert_se(memcmp_nn(p->unique.ecc.x.buffer, p->unique.ecc.x.size, expected_x, expected_x_len) == 0);

        DEFINE_HEX_PTR(expected_y, hexy);
        assert_se(memcmp_nn(p->unique.ecc.y.buffer, p->unique.ecc.y.size, expected_y, expected_y_len) == 0);

        check_tpm2b_public_fingerprint(&public, hexfp);
        check_tpm2b_public_name(&public, hexname);
}

static void check_tpm2b_public_from_rsa_pem(const char *pem, const char *hexn, uint32_t exponent, const char *hexfp, const char *hexname) {
        TPM2B_PUBLIC public = {};
        TPMT_PUBLIC *p = &public.publicArea;

        DEFINE_HEX_PTR(key, pem);
        get_tpm2b_public_from_pem(key, key_len, &public);

        assert_se(p->type == TPM2_ALG_RSA);

        DEFINE_HEX_PTR(expected_n, hexn);
        assert_se(memcmp_nn(p->unique.rsa.buffer, p->unique.rsa.size, expected_n, expected_n_len) == 0);

        assert_se(p->parameters.rsaDetail.keyBits == expected_n_len * 8);

        assert_se(p->parameters.rsaDetail.exponent == exponent);

        check_tpm2b_public_fingerprint(&public, hexfp);
        check_tpm2b_public_name(&public, hexname);
}

TEST(tpm2b_public_from_openssl_pkey) {
        // TODO: this test fails on s390x but only on Github Actions, re-enable once
        // https://github.com/systemd/systemd/issues/38229 is fixed
        if (strstr_ptr(ci_environment(), "github-actions") && uname_architecture() == ARCHITECTURE_S390X) {
                log_notice("%s: skipping test on GH Actions because of systemd/systemd#38229", __func__);
                return;
        }

        /* standard ECC key */
        check_tpm2b_public_from_ecc_pem("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145726a6e4575424c73496c3972687068777976584e50686a346a426e500a44586e794a304b395579724e6764365335413532542b6f5376746b436a365a726c34685847337741515558706f426c532b7448717452714c35513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
                                        "ae39c4b812ec225f6b869870caf5cd3e18f88c19cf0d79f22742bd532acd81de",
                                        "92e40e764fea12bed9028fa66b9788571b7c004145e9a01952fad1eab51a8be5",
                                        "cd3373293b62a52b48c12100e80ea9bfd806266ce76893a5ec31cb128052d97c",
                                        "000b5c127e4dbaf8fb7bac641e8db25a84a48db876ca7ee3bd317ae1a4554ff72f17");

        /* standard RSA key */
        check_tpm2b_public_from_rsa_pem("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541795639434950652f505852337a436f63787045300a6a575262546c3568585844436b472f584b79374b6d2f4439584942334b734f5a31436a5937375571372f674359363170697838697552756a73413464503165380a593445336c68556d374a332b6473766b626f4b64553243626d52494c2f6675627771694c4d587a41673342575278747234547545443533527a373634554650640a307a70304b68775231496230444c67772f344e67566f314146763378784b4d6478774d45683567676b73733038326332706c354a504e32587677426f744e6b4d0a5471526c745a4a35355244436170696e7153334577376675646c4e735851357746766c7432377a7637344b585165616d704c59433037584f6761304c676c536b0a79754774586b6a50542f735542544a705374615769674d5a6f714b7479563463515a58436b4a52684459614c47587673504233687a766d5671636e6b47654e540a65774944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
                                        "c95f4220f7bf3d7477cc2a1cc691348d645b4e5e615d70c2906fd72b2eca9bf0fd5c80772ac399d428d8efb52aeff80263ad698b1f22b91ba3b00e1d3f57bc638137961526ec9dfe76cbe46e829d53609b99120bfdfb9bc2a88b317cc0837056471b6be13b840f9dd1cfbeb85053ddd33a742a1c11d486f40cb830ff8360568d4016fdf1c4a31dc7030487982092cb34f36736a65e493cdd97bf0068b4d90c4ea465b59279e510c26a98a7a92dc4c3b7ee76536c5d0e7016f96ddbbcefef829741e6a6a4b602d3b5ce81ad0b8254a4cae1ad5e48cf4ffb140532694ad6968a0319a2a2adc95e1c4195c29094610d868b197bec3c1de1cef995a9c9e419e3537b",
                                        0x10001,
                                        "d9186d13a7fd5b3644cee05448f49ad3574e82a2942ff93cf89598d36cca78a9",
                                        "000be1bd75c7976e7a30e9e82223b81a9eff0d42c30618e588db592ed5da94455e81");

        /* RSA key with non-default (i.e. not 0x10001) exponent */
        check_tpm2b_public_from_rsa_pem("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b434151454179566c7551664b75565171596a5a71436a657a760a364e4a6f58654c736f702f72765375666330773769544d4f73566741557462515452505451725874397065537a4370524467634378656b6a544144577279304b0a6d59786a7a3634776c6a7030463959383068636a6b6b4b3759414d333054664c4648656c2b377574427370777142467a6e2b385a6659567353434b397354706f0a316c61376e5347514e7451576f36444a366c525a336a676d6d584f61544654416145304a432b7046584273564471736d46326438362f314e51714a755a5154520a575852636954704e58357649792f37766b6c5a6a685569526c78764e594f4e3070636476534a37364e74496e447a3048506f775a38705a454f4d2f4a454f59780a617a4c4a6a644936446b355279593578325a7949375074566a3057537242524f4d696f2b674c6556457a43343456336438315a38445138564e334c69625130330a70514944415141460a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
                                        "c9596e41f2ae550a988d9a828decefe8d2685de2eca29febbd2b9f734c3b89330eb1580052d6d04d13d342b5edf69792cc2a510e0702c5e9234c00d6af2d0a998c63cfae30963a7417d63cd217239242bb600337d137cb1477a5fbbbad06ca70a811739fef197d856c4822bdb13a68d656bb9d219036d416a3a0c9ea5459de382699739a4c54c0684d090bea455c1b150eab2617677cebfd4d42a26e6504d159745c893a4d5f9bc8cbfeef925663854891971bcd60e374a5c76f489efa36d2270f3d073e8c19f2964438cfc910e6316b32c98dd23a0e4e51c98e71d99c88ecfb558f4592ac144e322a3e80b7951330b8e15dddf3567c0d0f153772e26d0d37a5",
                                        0x10005,
                                        "c8ca80a687d5972e1d961aaa2cfde2ff2e7a20d85e3ea0382804e70e013d65af",
                                        "000beb8974d36d8cf58fdc87460dda00319e10c94c1b9f222ac9ce29d1c4776246cc");
}
#endif

static void check_name(const TPM2B_NAME *name, const char *expect) {
        assert_se(name->size == SHA256_DIGEST_SIZE + 2);

        DEFINE_HEX_PTR(e, expect);
        assert_se(name->size == e_len);
        assert_se(memcmp(name->name, e, e_len) == 0);
}

TEST(calculate_pubkey_name) {
        TPM2B_PUBLIC public;
        TPM2B_NAME name;

        /* RSA */
        tpm2b_public_rsa_init(&public, "9ec7341c52093ac40a1965a5df10432513c539adcf905e30577ab6ebc88ffe53cd08cef12ed9bec6125432f4fada3629b8b96d31b8f507aa35029188fe396da823fcb236027f7fbb01b0da3d87be7f999390449ced604bdf7e26c48657cc0671000f1147da195c3861c96642e54427cb7a11572e07567ec3fd6316978abc4bd92b27bb0a0e4958e599804eeb41d682b3b7fc1f960209f80a4fb8a1b64abfd96bf5d554e73cdd6ad1c8becb4fcf5e8f0c3e621d210e5e2f308f6520ad9a966779231b99f06c5989e5a23a9415c8808ab89ce81117632e2f8461cd4428bded40979236aeadafe8de3f51660a45e1dbc87694e6a36360201cca3ff9e7263e712727");
        assert_se(tpm2_calculate_pubkey_name(&public.publicArea, &name) >= 0);
        check_name(&name, "000be78f74a470dd92e979ca067cdb2293a35f075e8560b436bd2ccea5da21486a07");

        /* ECC */
        tpm2b_public_ecc_init(&public, TPM2_ECC_NIST_P256, "238e02ee4fd5598add6b502429f1815418515e4b0d6551c8e816b38cb15451d1", "70c2d491769775ec43ccd5a571c429233e9d30cf0f486c2e01acd6cb32ba93b6");
        assert_se(tpm2_calculate_pubkey_name(&public.publicArea, &name) >= 0);
        check_name(&name, "000b302787187ba19c82011c987bd2dcdbb652b3a543ccc5cb0b49c33d4caae604a6");
}

TEST(calculate_policy_auth_value) {
        TPM2B_DIGEST d;

        digest_init(&d, "0000000000000000000000000000000000000000000000000000000000000000");
        assert_se(tpm2_calculate_policy_auth_value(&d) == 0);
        assert_se(digest_check(&d, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"));
        assert_se(tpm2_calculate_policy_auth_value(&d) == 0);
        assert_se(digest_check(&d, "759ebd5ed65100e0b4aa2d04b4b789c2672d92ecc9cdda4b5fa16a303132e008"));
}

TEST(calculate_policy_authorize) {
        TPM2B_PUBLIC public;
        TPM2B_DIGEST d;

        /* RSA */
        tpm2b_public_rsa_init(&public, "9ec7341c52093ac40a1965a5df10432513c539adcf905e30577ab6ebc88ffe53cd08cef12ed9bec6125432f4fada3629b8b96d31b8f507aa35029188fe396da823fcb236027f7fbb01b0da3d87be7f999390449ced604bdf7e26c48657cc0671000f1147da195c3861c96642e54427cb7a11572e07567ec3fd6316978abc4bd92b27bb0a0e4958e599804eeb41d682b3b7fc1f960209f80a4fb8a1b64abfd96bf5d554e73cdd6ad1c8becb4fcf5e8f0c3e621d210e5e2f308f6520ad9a966779231b99f06c5989e5a23a9415c8808ab89ce81117632e2f8461cd4428bded40979236aeadafe8de3f51660a45e1dbc87694e6a36360201cca3ff9e7263e712727");
        digest_init(&d, "0000000000000000000000000000000000000000000000000000000000000000");
        assert_se(tpm2_calculate_policy_authorize(&public, NULL, &d) == 0);
        assert_se(digest_check(&d, "95213a3784eaab04f427bc7e8851c2f1df0903be8e42428ec25dcefd907baff1"));
        assert_se(tpm2_calculate_policy_authorize(&public, NULL, &d) == 0);
        assert_se(digest_check(&d, "95213a3784eaab04f427bc7e8851c2f1df0903be8e42428ec25dcefd907baff1"));

        /* ECC */
        tpm2b_public_ecc_init(&public, TPM2_ECC_NIST_P256, "423a89da6f0998f510489ab9682706e762031ef8f9faef2a185eff67065a187e", "996f73291670cef9e303d6cd9fa19ddf2c9c1fb1e283324ca9acca07c405c8d0");
        digest_init(&d, "0000000000000000000000000000000000000000000000000000000000000000");
        assert_se(tpm2_calculate_policy_authorize(&public, NULL, &d) == 0);
        assert_se(digest_check(&d, "2a5b705e83f949c27ac4d2e79e54fb5fb0a60f0b37bbd54a0ee1022ba00d3628"));
        assert_se(tpm2_calculate_policy_authorize(&public, NULL, &d) == 0);
        assert_se(digest_check(&d, "2a5b705e83f949c27ac4d2e79e54fb5fb0a60f0b37bbd54a0ee1022ba00d3628"));
}

TEST(calculate_policy_pcr) {
        TPM2B_DIGEST d, dN[16];

        digest_init(&dN[ 0], "2124793cbbe60c3a8637d3b84a5d054e87c351e1469a285acc04755e8b204dec");
        digest_init(&dN[ 1], "bf7592f18adcfdc549fc0b94939f5069a24697f9cff4a0dca29014767b97559d");
        digest_init(&dN[ 2], "4b00cff9dee3a364979b2dc241b34568a8ad49fcf2713df259e47dff8875feed");
        digest_init(&dN[ 3], "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969");
        digest_init(&dN[ 4], "368f85b3013041dfe203faaa364f00b07c5da7b1e5f1dbf2efb06fa6b9bd92de");
        digest_init(&dN[ 5], "c97c40369691c8e4aa78fb3a52655cd193b780a838b8e23f5f476576919db5e5");
        digest_init(&dN[ 6], "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969");
        digest_init(&dN[ 7], "aa1154c9e0a774854ccbed4c8ce7e9b906b3d700a1a8db1772d0341a62dbe51b");
        digest_init(&dN[ 8], "cfde439a2c06af3479ca6bdc60429b90553d65300c5cfcc40004a08c6b5ad81a");
        digest_init(&dN[ 9], "9c2bac22ef5ec84fcdb71c3ebf776cba1247e5da980e5ee08e45666a2edf0b8b");
        digest_init(&dN[10], "9885873f4d7348199ad286f8f2476d4f866940950f6f9fb9f945ed352dbdcbd2");
        digest_init(&dN[11], "42400ab950d21aa79d12cc4fdef67d1087a39ad64900619831c0974dbae54e44");
        digest_init(&dN[12], "767d064382e56ca1ad3bdcc6bc596112e6c2008b593d3570d24c2bfa64c4628c");
        digest_init(&dN[13], "30c16133175959408c9745d8dafadef5daf4b39cb2be04df0d60089bd46d3cc4");
        digest_init(&dN[14], "e3991b7ddd47be7e92726a832d6874c5349b52b789fa0db8b558c69fea29574e");
        digest_init(&dN[15], "852dae3ecb992bdeb13d6002fefeeffdd90feca8b378d56681ef2c885d0e5137");

        digest_init(&d, "0000000000000000000000000000000000000000000000000000000000000000");
        Tpm2PCRValue v1[] = {
                TPM2_PCR_VALUE_MAKE(4, TPM2_ALG_SHA256, dN[4]),
                TPM2_PCR_VALUE_MAKE(7, TPM2_ALG_SHA256, dN[7]),
                TPM2_PCR_VALUE_MAKE(8, TPM2_ALG_SHA256, dN[8]),
        };
        assert_se(tpm2_calculate_policy_pcr(v1, ELEMENTSOF(v1), &d) == 0);
        assert_se(digest_check(&d, "76532a0e16f7e6bf6b02918c11f75d99d729fab0cc81d0df2c4284a2c4fe6e05"));
        assert_se(tpm2_calculate_policy_pcr(v1, ELEMENTSOF(v1), &d) == 0);
        assert_se(digest_check(&d, "97e64bcabb64c1fa4b726528644926c8029f5b4458b0575c98c04fe225629a0b"));

        digest_init(&d, "0000000000000000000000000000000000000000000000000000000000000000");
        Tpm2PCRValue v2[] = {
                TPM2_PCR_VALUE_MAKE( 0, TPM2_ALG_SHA256, dN[ 0]),
                TPM2_PCR_VALUE_MAKE( 1, TPM2_ALG_SHA256, dN[ 1]),
                TPM2_PCR_VALUE_MAKE( 2, TPM2_ALG_SHA256, dN[ 2]),
                TPM2_PCR_VALUE_MAKE( 3, TPM2_ALG_SHA256, dN[ 3]),
                TPM2_PCR_VALUE_MAKE( 4, TPM2_ALG_SHA256, dN[ 4]),
                TPM2_PCR_VALUE_MAKE( 5, TPM2_ALG_SHA256, dN[ 5]),
                TPM2_PCR_VALUE_MAKE( 6, TPM2_ALG_SHA256, dN[ 6]),
                TPM2_PCR_VALUE_MAKE( 7, TPM2_ALG_SHA256, dN[ 7]),
                TPM2_PCR_VALUE_MAKE( 8, TPM2_ALG_SHA256, dN[ 8]),
                TPM2_PCR_VALUE_MAKE( 9, TPM2_ALG_SHA256, dN[ 9]),
                TPM2_PCR_VALUE_MAKE(10, TPM2_ALG_SHA256, dN[10]),
                TPM2_PCR_VALUE_MAKE(11, TPM2_ALG_SHA256, dN[11]),
                TPM2_PCR_VALUE_MAKE(12, TPM2_ALG_SHA256, dN[12]),
                TPM2_PCR_VALUE_MAKE(13, TPM2_ALG_SHA256, dN[13]),
                TPM2_PCR_VALUE_MAKE(14, TPM2_ALG_SHA256, dN[14]),
                TPM2_PCR_VALUE_MAKE(15, TPM2_ALG_SHA256, dN[15]),
        };
        assert_se(tpm2_calculate_policy_pcr(v2, ELEMENTSOF(v2), &d) == 0);
        assert_se(digest_check(&d, "22be4f1674f792d6345cea9427701068f0e8d9f42755dcc0e927e545a68f9c13"));
        assert_se(tpm2_calculate_policy_pcr(v2, ELEMENTSOF(v2), &d) == 0);
        assert_se(digest_check(&d, "7481fd1b116078eb3ac2456e4ad542c9b46b9b8eb891335771ca8e7c8f8e4415"));
}

static void check_srk_rsa_template(TPMT_PUBLIC *template) {
        assert_se(template->type == TPM2_ALG_RSA);
        assert_se(template->nameAlg == TPM2_ALG_SHA256);
        assert_se(template->objectAttributes == 0x30472);
        assert_se(template->parameters.rsaDetail.symmetric.algorithm == TPM2_ALG_AES);
        assert_se(template->parameters.rsaDetail.symmetric.keyBits.sym == 128);
        assert_se(template->parameters.rsaDetail.symmetric.mode.sym == TPM2_ALG_CFB);
        assert_se(template->parameters.rsaDetail.scheme.scheme == TPM2_ALG_NULL);
        assert_se(template->parameters.rsaDetail.keyBits == 2048);
}

static void check_srk_ecc_template(TPMT_PUBLIC *template) {
        assert_se(template->type == TPM2_ALG_ECC);
        assert_se(template->nameAlg == TPM2_ALG_SHA256);
        assert_se(template->objectAttributes == 0x30472);
        assert_se(template->parameters.eccDetail.symmetric.algorithm == TPM2_ALG_AES);
        assert_se(template->parameters.eccDetail.symmetric.keyBits.sym == 128);
        assert_se(template->parameters.eccDetail.symmetric.mode.sym == TPM2_ALG_CFB);
        assert_se(template->parameters.eccDetail.scheme.scheme == TPM2_ALG_NULL);
        assert_se(template->parameters.eccDetail.kdf.scheme == TPM2_ALG_NULL);
        assert_se(template->parameters.eccDetail.curveID == TPM2_ECC_NIST_P256);
}

TEST(tpm2_get_srk_template) {
        TPMT_PUBLIC template;

        assert_se(tpm2_get_srk_template(TPM2_ALG_RSA, &template) >= 0);
        check_srk_rsa_template(&template);

        assert_se(tpm2_get_srk_template(TPM2_ALG_ECC, &template) >= 0);
        check_srk_ecc_template(&template);
}

static void check_best_srk_template(Tpm2Context *c) {
        TEST_LOG_FUNC();

        TPMT_PUBLIC template;
        assert_se(tpm2_get_best_srk_template(c, &template) >= 0);

        assert_se(IN_SET(template.type, TPM2_ALG_ECC, TPM2_ALG_RSA));

        if (template.type == TPM2_ALG_RSA)
                check_srk_rsa_template(&template);
        else
                check_srk_ecc_template(&template);
}

static void check_test_parms(Tpm2Context *c) {
        assert(c);

        TEST_LOG_FUNC();

        TPMU_PUBLIC_PARMS parms = {
                .symDetail.sym = {
                        .algorithm = TPM2_ALG_AES,
                        .keyBits.aes = 128,
                        .mode.aes = TPM2_ALG_CFB,
                },
        };

        /* Test with invalid parms */
        assert_se(!tpm2_test_parms(c, TPM2_ALG_CFB, &parms));

        TPMU_PUBLIC_PARMS invalid_parms = parms;
        invalid_parms.symDetail.sym.keyBits.aes = 1;
        assert_se(!tpm2_test_parms(c, TPM2_ALG_SYMCIPHER, &invalid_parms));

        /* Test with valid parms */
        assert_se(tpm2_test_parms(c, TPM2_ALG_SYMCIPHER, &parms));
}

static void check_supports_alg(Tpm2Context *c) {
        assert(c);

        TEST_LOG_FUNC();

        /* Test invalid algs */
        assert_se(!tpm2_supports_alg(c, TPM2_ALG_ERROR));
        assert_se(!tpm2_supports_alg(c, TPM2_ALG_LAST + 1));

        /* Test valid algs */
        assert_se(tpm2_supports_alg(c, TPM2_ALG_RSA));
        assert_se(tpm2_supports_alg(c, TPM2_ALG_AES));
        assert_se(tpm2_supports_alg(c, TPM2_ALG_CFB));
}

static void check_supports_command(Tpm2Context *c) {
        assert(c);

        TEST_LOG_FUNC();

        /* Test invalid commands. TPM specification Part 2 ("Structures") section "TPM_CC (Command Codes)"
         * states bits 31:30 and 28:16 are reserved and must be 0. */
        assert_se(!tpm2_supports_command(c, UINT32_C(0x80000000)));
        assert_se(!tpm2_supports_command(c, UINT32_C(0x40000000)));
        assert_se(!tpm2_supports_command(c, UINT32_C(0x00100000)));
        assert_se(!tpm2_supports_command(c, UINT32_C(0x80000144)));
        assert_se(!tpm2_supports_command(c, UINT32_C(0x40000144)));
        assert_se(!tpm2_supports_command(c, UINT32_C(0x00100144)));

        /* Test valid commands. We should be able to expect all TPMs support these. */
        assert_se(tpm2_supports_command(c, TPM2_CC_Startup));
        assert_se(tpm2_supports_command(c, TPM2_CC_StartAuthSession));
        assert_se(tpm2_supports_command(c, TPM2_CC_Create));
        assert_se(tpm2_supports_command(c, TPM2_CC_CreatePrimary));
        assert_se(tpm2_supports_command(c, TPM2_CC_Unseal));
}

static void check_get_or_create_srk(Tpm2Context *c) {
        TEST_LOG_FUNC();

        _cleanup_free_ TPM2B_PUBLIC *public = NULL;
        _cleanup_free_ TPM2B_NAME *name = NULL, *qname = NULL;
        _cleanup_(tpm2_handle_freep) Tpm2Handle *handle = NULL;
        assert_se(tpm2_get_or_create_srk(c, NULL, &public, &name, &qname, &handle) >= 0);
        assert_se(public && name && qname && handle);

        _cleanup_free_ TPM2B_PUBLIC *public2 = NULL;
        _cleanup_free_ TPM2B_NAME *name2 = NULL, *qname2 = NULL;
        _cleanup_(tpm2_handle_freep) Tpm2Handle *handle2 = NULL;
        assert_se(tpm2_get_srk(c, NULL, &public2, &name2, &qname2, &handle2) >= 0);
        assert_se(public2 && name2 && qname2 && handle2);

        assert_se(memcmp_nn(public, sizeof(*public), public2, sizeof(*public2)) == 0);
        assert_se(memcmp_nn(name->name, name->size, name2->name, name2->size) == 0);
        assert_se(memcmp_nn(qname->name, qname->size, qname2->name, qname2->size) == 0);
}

#if HAVE_OPENSSL
static void calculate_seal_and_unseal(
                Tpm2Context *c,
                TPM2_HANDLE parent_index,
                const TPM2B_PUBLIC *parent_public) {

        _cleanup_free_ char *secret_string = NULL;
        assert_se(asprintf(&secret_string, "The classified documents are in room %x", parent_index) > 0);
        size_t secret_size = strlen(secret_string) + 1;

        _cleanup_(iovec_done) struct iovec blob = {}, serialized_parent = {};
        assert_se(tpm2_calculate_seal(
                        parent_index,
                        parent_public,
                        /* attributes= */ NULL,
                        &IOVEC_MAKE(secret_string, secret_size),
                        /* policy= */ NULL,
                        /* pin= */ NULL,
                        /* ret_secret= */ NULL,
                        &blob,
                        &serialized_parent) >= 0);

        _cleanup_(iovec_done) struct iovec unsealed_secret = {};
        assert_se(tpm2_unseal(
                        c,
                        /* hash_pcr_mask= */ 0,
                        /* pcr_bank= */ 0,
                        /* pubkey= */ NULL,
                        /* pubkey_pcr_mask= */ 0,
                        /* signature= */ NULL,
                        /* pin= */ NULL,
                        /* pcrlock_policy= */ NULL,
                        /* primary_alg= */ 0,
                        &blob,
                        /* n_blobs= */ 1,
                        /* known_policy_hash= */ NULL,
                        /* n_known_policy_hash= */ 0,
                        &serialized_parent,
                        &unsealed_secret) >= 0);

        assert_se(memcmp_nn(secret_string, secret_size, unsealed_secret.iov_base, unsealed_secret.iov_len) == 0);

        char unsealed_string[unsealed_secret.iov_len];
        assert_se(snprintf(unsealed_string, unsealed_secret.iov_len, "%s", (char*) unsealed_secret.iov_base) == (int) unsealed_secret.iov_len - 1);
        log_debug("Unsealed secret is: %s", unsealed_string);
}

static int check_calculate_seal(Tpm2Context *c) {
        assert(c);
        int r;

        if (detect_virtualization() == VIRTUALIZATION_NONE && !slow_tests_enabled()) {
                log_notice("Skipping slow calculate seal TPM2 tests. Physical system detected, and slow tests disabled. (To enable, run again with $SYSTEMD_SLOW_TESTS=1.)");
                return 0;
        }

        TEST_LOG_FUNC();

        _cleanup_free_ TPM2B_PUBLIC *srk_public = NULL;
        assert_se(tpm2_get_srk(c, NULL, &srk_public, NULL, NULL, NULL) >= 0);
        calculate_seal_and_unseal(c, TPM2_SRK_HANDLE, srk_public);

        TPMI_ALG_ASYM test_algs[] = { TPM2_ALG_RSA, TPM2_ALG_ECC, };
        FOREACH_ELEMENT(alg, test_algs) {
                TPM2B_PUBLIC template = { .size = sizeof(TPMT_PUBLIC), };
                assert_se(tpm2_get_srk_template(*alg, &template.publicArea) >= 0);

                _cleanup_free_ TPM2B_PUBLIC *public = NULL;
                _cleanup_(tpm2_handle_freep) Tpm2Handle *handle = NULL;
                assert_se(tpm2_create_primary(c, NULL, &template, NULL, &public, &handle) >= 0);

                /* Once our minimum libtss2-esys version is 2.4.0 or later, this can assume
                 * tpm2_index_from_handle() should always work. */
                TPM2_HANDLE index;
                r = tpm2_index_from_handle(c, handle, &index);
                if (r == -EOPNOTSUPP)
                        return log_tests_skipped("libtss2-esys version too old to support tpm2_index_from_handle()");
                assert_se(r >= 0);

                calculate_seal_and_unseal(c, index, public);
        }

        return 0;
}
#endif /* HAVE_OPENSSL */

static void check_seal_unseal_for_handle(Tpm2Context *c, TPM2_HANDLE handle) {
        TPM2B_DIGEST policy = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);

        assert(c);

        log_debug("Check seal/unseal for handle 0x%" PRIx32, handle);

        _cleanup_(iovec_done) struct iovec secret = {}, srk = {}, unsealed_secret = {};
        struct iovec *blobs = NULL;
        size_t n_blobs = 0;
        CLEANUP_ARRAY(blobs, n_blobs, iovec_array_free);

        assert_se(tpm2_seal(
                        c,
                        handle,
                        &policy,
                        1,
                        /* pin= */ NULL,
                        &secret,
                        &blobs,
                        &n_blobs,
                        /* ret_primary_alg= */ NULL,
                        &srk) >= 0);

        assert_se(tpm2_unseal(
                        c,
                        /* hash_pcr_mask= */ 0,
                        /* pcr_bank= */ 0,
                        /* pubkey= */ NULL,
                        /* pubkey_pcr_mask= */ 0,
                        /* signature= */ NULL,
                        /* pin= */ NULL,
                        /* pcrlock_policy= */ NULL,
                        /* primary_alg= */ 0,
                        blobs,
                        n_blobs,
                        /* known_policy_hash= */ NULL,
                        /* n_known_policy_hash= */ 0,
                        &srk,
                        &unsealed_secret) >= 0);

        assert_se(iovec_memcmp(&secret, &unsealed_secret) == 0);
}

static void check_seal_unseal(Tpm2Context *c) {
        int r;

        assert(c);

        if (detect_virtualization() == VIRTUALIZATION_NONE && !slow_tests_enabled()) {
                log_notice("Skipping slow seal/unseal TPM2 tests. Physical system detected, and slow tests disabled. (To enable, run again with $SYSTEMD_SLOW_TESTS=1.)");
                return;
        }

        TEST_LOG_FUNC();

        check_seal_unseal_for_handle(c, 0);
        check_seal_unseal_for_handle(c, TPM2_SRK_HANDLE);

        FOREACH_ELEMENT(template, test_templates) {
                TPM2B_PUBLIC public = {
                        .publicArea = **template,
                        .size = sizeof(**template),
                };
                _cleanup_(tpm2_handle_freep) Tpm2Handle *transient_handle = NULL;
                assert_se(tpm2_create_primary(
                                c,
                                /* session= */ NULL,
                                &public,
                                /* sensitive= */ NULL,
                                /* ret_public= */ NULL,
                                &transient_handle) >= 0);

                TPMI_DH_PERSISTENT transient_handle_index;
                r = tpm2_index_from_handle(c, transient_handle, &transient_handle_index);
                if (r == -EOPNOTSUPP) {
                        /* libesys too old */
                        log_tests_skipped("libesys too old for tpm2_index_from_handle");
                        return;
                }
                assert_se(r >= 0);

                check_seal_unseal_for_handle(c, transient_handle_index);
        }
}

TEST_RET(tests_which_require_tpm) {
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r = 0;

        if (tpm2_context_new(NULL, &c) < 0)
                return log_tests_skipped("Could not find TPM");

        check_test_parms(c);
        check_supports_alg(c);
        check_supports_command(c);
        check_best_srk_template(c);
        check_get_or_create_srk(c);
        check_seal_unseal(c);

#if HAVE_OPENSSL
        r = check_calculate_seal(c);
#endif

        return r;
}

#endif /* HAVE_TPM2 */

DEFINE_TEST_MAIN(LOG_DEBUG);
