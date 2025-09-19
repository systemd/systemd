/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef NTS_STANDALONE_TEST
#    include "tests.h"
#    include "timesyncd-conf.h"
#else
#    define _GNU_SOURCE 1
#    include <assert.h>
#    define HAVE_OPENSSL 1
#    define assert_se assert
#    define TEST(name) static void test_##name(void)
#    define DEFINE_TEST_MAIN(_ignore) int main(void) { \
        test_nts_encoding(); \
        test_nts_decoding(); \
        test_ntp_field_encoding(); \
        test_ntp_field_decoding(); \
        test_crypto(); \
        test_keysize(); \
        return 0; \
     } int _placeholder
#endif

#include <string.h>
#include <stdio.h>

#include "nts.h"
#include "nts_extfields.h"
#include "nts_crypto.h"

#if HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wshadow"

/* it's the callers job to ensure bounds are not transgressed */
#define encode_record_raw(msg, type, data, len) encode_ptr_len_data(msg, type, data, len, 0)
#define encode_record_raw_ext(msg, type, data, len) encode_ptr_len_data(msg, type, data, len, 1)

static void encode_ptr_len_data(
                uint8_t **message,
                uint16_t type,
                const void *data,
                uint16_t len,
                int count_hdr) {

        uint8_t hdr[4] = {
                type >> 8,
                type & 0xFF,
                (len + count_hdr*sizeof(hdr)) >> 8,
                (len + count_hdr*sizeof(hdr)) & 0xFF,
        };

        memcpy(*message, hdr, 4);
        if (len) memcpy(*message+4, data, len);
        *message += len + 4;
}

TEST(nts_encoding) {
        uint8_t buffer[1000];
        struct NTS_Agreement rec;

        NTS_encode_request(buffer, sizeof buffer, NULL);
        assert_se(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert_se(rec.error == NTS_SUCCESS);
        assert_se(rec.ntp_server == NULL);
        assert_se(rec.ntp_port == 0);
        assert_se(rec.cookie[0].data == NULL);
        assert_se(rec.cookie[0].length == 0);
        assert_se(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

        uint16_t proto1[] = { NTS_AEAD_AES_SIV_CMAC_256, NTS_AEAD_AES_SIV_CMAC_512, 0 };
        NTS_encode_request(buffer, sizeof buffer, proto1);
        assert_se(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert_se(rec.error == NTS_SUCCESS);
        assert_se(rec.ntp_server == NULL);
        assert_se(rec.ntp_port == 0);
        assert_se(rec.cookie[0].data == NULL);
        assert_se(rec.cookie[0].length == 0);
        assert_se(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

        uint16_t proto2[] = { NTS_AEAD_AES_SIV_CMAC_512, NTS_AEAD_AES_SIV_CMAC_256, 0 };
        NTS_encode_request(buffer, sizeof buffer, proto2);
        assert_se(NTS_decode_response(buffer, 1000, &rec) == 0);
        assert_se(rec.error == NTS_SUCCESS);
        assert_se(rec.ntp_server == NULL);
        assert_se(rec.ntp_port == 0);
        assert_se(rec.cookie[0].data == NULL);
        assert_se(rec.cookie[0].length == 0);
        assert_se(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_512);
}

TEST(nts_decoding) {
        uint8_t buffer[0x10000], *p;
        struct NTS_Agreement rec;

        /* empty */
        uint8_t value[2] = { 0, };
        encode_record_raw((p = buffer, &p), 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_BAD_RESPONSE);

        /* missing aead */
        encode_record_raw((p = buffer, &p), 1, &value, 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_BAD_RESPONSE);

        /* missing nextproto */
        encode_record_raw((p = buffer, &p), 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_BAD_RESPONSE);

        /* invalid nextproto */
        encode_record_raw((p = buffer, &p), 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 1, (value[1] = 3, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_NO_PROTOCOL);

        /* invalid aead */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 37, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_NO_AEAD);

        /* unknown critical record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 0xfe | 0x8000, &value, 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_UNKNOWN_CRIT_RECORD);

        /* error record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 2, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == 42);

        /* warning record */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 3, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 0, NULL, 0);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
        assert_se(rec.error == NTS_UNEXPECTED_WARNING);

        /* valid */
        encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
        encode_record_raw(&p, 5, "COOKIE1", 7);
        encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
        encode_record_raw(&p, 5, "COOKIE22", 8);
        encode_record_raw(&p, 0xee, "unknown", 7);
        encode_record_raw(&p, 7, (value[1] = 42, &value), 2);
        encode_record_raw(&p, 5, "COOKIE333", 9);
        encode_record_raw(&p, 6, "localhost", 9);
        encode_record_raw(&p, 5, "COOKIE4444", 10);
        assert_se(NTS_decode_response(buffer, sizeof buffer, &rec) == 0);
        assert_se(rec.error == NTS_SUCCESS);
        assert_se(rec.aead_id == 15);
        assert_se(rec.ntp_port == 42);
        assert_se(strcmp(rec.ntp_server, "localhost") == 0);
        assert_se(memcmp(rec.cookie[0].data, "COOKIE1", rec.cookie[0].length) == 0);
        assert_se(memcmp(rec.cookie[1].data, "COOKIE22", rec.cookie[1].length) == 0);
        assert_se(memcmp(rec.cookie[2].data, "COOKIE333", rec.cookie[2].length) == 0);
        assert_se(memcmp(rec.cookie[3].data, "COOKIE4444", rec.cookie[3].length) == 0);
        assert_se(rec.cookie[4].data == NULL);
        assert_se(rec.cookie[4].length == 0);
}

TEST(ntp_field_encoding) {
        uint8_t buffer[1280];

        uint8_t key[32] = { 0, };
        char cookie[] = "PAD";

        struct NTS_Query nts = {
                { (uint8_t*)cookie, strlen(cookie) },
                key,
                key,
                *NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256),
        };

        struct NTS_Receipt rcpt = { 0, };
        int len = NTS_add_extension_fields(&buffer, &nts, NULL);
        assert_se(len > 48);
        assert_se(NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));

        assert_se(rcpt.new_cookie->data == NULL);
        assert_se(memcmp(buffer + 48 + 36 + 4, cookie, strlen(cookie)) == 0);
        assert_se(strcmp((char*)buffer + 48 + 36 + 4, cookie) == 0);

        for (int i=0; i < len; i++) {
                zero(rcpt);
                len = NTS_add_extension_fields(&buffer, &nts, NULL);
                buffer[i] ^= 0x20;
                assert_se(!NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));
        }

        zero(rcpt);
        len = NTS_add_extension_fields(&buffer, &nts, NULL);
        nts.s2c_key = (uint8_t[32]){ 1, };
        assert_se(!NTS_parse_extension_fields(&buffer, len, &nts, &rcpt));
}

#if HAVE_OPENSSL
static void add_encrypted_server_hdr(
                uint8_t *buffer,
                uint8_t **p_ptr,
                struct NTS_Query nts,
                const char *cookie[],
                uint8_t *corrupt) {

        uint8_t *af = *p_ptr;
        uint8_t *pt;
        /* write nonce */
        *p_ptr = pt = (uint8_t*)mempcpy(af+8, "123NONCE", 8) + 16;
        /* write fields */
        encode_record_raw_ext(p_ptr, 0x0104, "A sharp mind cuts through deceit", 32);
        for ( ; *cookie; cookie++)
                encode_record_raw_ext(p_ptr, 0x0204, *cookie, strlen(*cookie));

        /* corrupt a byte */
        if (corrupt) *corrupt = 0xee;

        /* encrypt fields */
        EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-SIV", NULL);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int ignore;
        EVP_EncryptInit_ex(ctx, cipher, NULL, nts.s2c_key, NULL);
        EVP_EncryptUpdate(ctx, NULL, &ignore, buffer, af - buffer);
        EVP_EncryptUpdate(ctx, NULL, &ignore, (uint8_t*)"123NONCE", 8);
        EVP_EncryptUpdate(ctx, pt, &ignore, pt, *p_ptr - pt);
        EVP_EncryptFinal_ex(ctx, buffer, &ignore);
        assert_se(ignore == 0);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, pt - 16);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);

        /* set type to 0x404 */
        memzero(af, 8);
        af[0] = af[1] = 0x04;
        /* set overall packet length */
        af[3] = *p_ptr - af;
        /* set nonce length */
        af[5] = 8;
        /* set ciphertext length */
        af[7] = *p_ptr - pt + 16;
}

TEST(ntp_field_decoding) {
        uint8_t buffer[1280];

        char cookie[] = "COOKIE", cakey[] = "CAKEY";
        uint8_t key[32] = { 0, };

        struct NTS_Query nts = {
                { (uint8_t*)cookie, strlen(cookie) },
                key,
                key,
                *NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256),
        };

        uint8_t *p =  buffer + 48;

        char ident[32] = "Silence speaks louder than words";

        /* this deliberately breaks padding rules and sneaks an encrypted identifier */
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        add_encrypted_server_hdr(buffer, &p, nts, (const char*[]){cookie, cakey, NULL}, NULL);

        struct NTS_Receipt rcpt = { 0, };
        assert_se(NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        assert_se(memcmp(rcpt.identifier, ident, 32) == 0);
        assert_se(rcpt.new_cookie[0].data != NULL);
        assert_se(rcpt.new_cookie[0].length >= strlen(cookie));
        assert_se(memcmp(rcpt.new_cookie[0].data, cookie, strlen(cookie)) == 0);
        assert_se(rcpt.new_cookie[1].data != NULL);
        assert_se(rcpt.new_cookie[1].length >= strlen(cakey));
        assert_se(memcmp(rcpt.new_cookie[1].data, cakey, strlen(cakey)) == 0);
        assert_se(rcpt.new_cookie[2].data == NULL);

        /* same test but no authentication of uniq id */
        p = buffer + 48;
        add_encrypted_server_hdr(buffer, &p, nts, (const char*[]){cookie, NULL}, NULL);
        encode_record_raw_ext(&p, 0x0104, ident, 32);

        zero(rcpt);
        assert_se(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* no authentication at all */
        p = buffer + 48;
        encode_record_raw(&p, 0x0104, ident, 32);
        zero(rcpt);
        assert_se(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* malicious unencrypted field */
        p = buffer + 48;
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        add_encrypted_server_hdr(buffer, &p, nts, (const char*[]){cookie, NULL}, NULL);
        buffer[48+2] = 0xee;
        zero(rcpt);
        assert_se(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));

        /* malicious encrypted field */
        p = buffer + 48;
        encode_record_raw_ext(&p, 0x0104, ident, 32);
        /* at p+32 the first plaintext data will be written
         * so at p+34 is the MSB of the first field length */
        add_encrypted_server_hdr(buffer, &p, nts, (const char*[]){cookie, NULL}, p+34);

        zero(rcpt);
        assert_se(!NTS_parse_extension_fields(&buffer, p - buffer, &nts, &rcpt));
}
#endif

/* appease the gcc static analyzer */
static const void* nonnull(const void *p) {
        assert_se(p);
        return p;
}

TEST(crypto) {
        uint8_t key[256];
        uint8_t enc[100], dec[100];
        const uint8_t plaintext[] = "attack at down";

        for (unsigned i = 0; i < sizeof(key); i++) key[i] = i * 0x11 & 0xFF;

        const AssociatedData ad[] = {
                { (uint8_t*)"FNORD", 5 },
                { (uint8_t*)"XXXXNONCEXXX", 12 },
                { NULL },
        };

        /* test roundtrips for all ciphers */
        for (unsigned id=0; id <= 33; id++) {
                if (!NTS_get_param(id)) continue;
                int len = NTS_encrypt(enc, plaintext, sizeof(plaintext), ad, nonnull(NTS_get_param(id)), key);
                assert_se(len > 0);
                assert_se(NTS_decrypt(dec, enc, len, ad, nonnull(NTS_get_param(id)), key) == sizeof(plaintext));
                assert_se(memcmp(dec, plaintext, sizeof(plaintext)) == 0);
        }

        /* test in-place decryption for the default cipher */
        memcpy(enc, plaintext, sizeof(plaintext));
        int len = NTS_encrypt(enc, enc, sizeof(plaintext), ad, nonnull(NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256)), key);
        assert_se(len == sizeof(plaintext)+16);
        assert_se(NTS_decrypt(enc, enc, len, ad, nonnull(NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256)), key) == sizeof(plaintext));
        assert_se(memcmp(enc, plaintext, sizeof(plaintext)) == 0);

        /* test known vectors AES_SIV_CMAC_256
         * we can't test these using Nettle; one way to check that we are on Nettle is currently that it does not
         * support SIV_CMAC_384
         */
        if (NTS_get_param(NTS_AEAD_AES_SIV_CMAC_384)) {

                uint8_t key[] = {
                        0x7f,0x7e,0x7d,0x7c, 0x7b,0x7a,0x79,0x78, 0x77,0x76,0x75,0x74, 0x73,0x72,0x71,0x70,
                        0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47, 0x48,0x49,0x4a,0x4b, 0x4c,0x4d,0x4e,0x4f,
                };


                uint8_t aad1[] = {
                        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77, 0x88,0x99,0xaa,0xbb, 0xcc,0xdd,0xee,0xff,
                        0xde,0xad,0xda,0xda, 0xde,0xad,0xda,0xda, 0xff,0xee,0xdd,0xcc, 0xbb,0xaa,0x99,0x88,
                        0x77,0x66,0x55,0x44, 0x33,0x22,0x11,0x00,
                };
                uint8_t aad2[] = {
                        0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80, 0x90,0xa0,
                };

                uint8_t nonce[] = {
                        0x09,0xf9,0x11,0x02, 0x9d,0x74,0xe3,0x5b, 0xd8,0x41,0x56,0xc5, 0x63,0x56,0x88,0xc0,
                };

                uint8_t pt[] = {
                        0x74,0x68,0x69,0x73, 0x20,0x69,0x73,0x20, 0x73,0x6f,0x6d,0x65, 0x20,0x70,0x6c,0x61,
                        0x69,0x6e,0x74,0x65, 0x78,0x74,0x20,0x74, 0x6f,0x20,0x65,0x6e, 0x63,0x72,0x79,0x70,
                        0x74,0x20,0x75,0x73, 0x69,0x6e,0x67,0x20, 0x53,0x49,0x56,0x2d, 0x41,0x45,0x53
                };
                uint8_t ct[] = {
                        0x7b,0xdb,0x6e,0x3b, 0x43,0x26,0x67,0xeb, 0x06,0xf4,0xd1,0x4b, 0xff,0x2f,0xbd,0x0f,
                        0xcb,0x90,0x0f,0x2f, 0xdd,0xbe,0x40,0x43, 0x26,0x60,0x19,0x65, 0xc8,0x89,0xbf,0x17,
                        0xdb,0xa7,0x7c,0xeb, 0x09,0x4f,0xa6,0x63, 0xb7,0xa3,0xf7,0x48, 0xba,0x8a,0xf8,0x29,
                        0xea,0x64,0xad,0x54, 0x4a,0x27,0x2e,0x9c, 0x48,0x5b,0x62,0xa3, 0xfd,0x5c,0x0d,
                };

                uint8_t out[sizeof(ct)];

                const AssociatedData info[] = {
                        { aad1, sizeof(aad1) },
                        { aad2, sizeof(aad2) },
                        { nonce, sizeof(nonce) },
                        { NULL }
                };
                assert_se(NTS_encrypt(out, pt, sizeof(pt), info, NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256), key) == sizeof(ct));
                assert_se(memcmp(out, ct, sizeof(ct)) == 0);
        }

        /* test known vectors - AES_128_GCM_SIV */
        if (NTS_get_param(NTS_AEAD_AES_128_GCM_SIV)) {
                uint8_t key[16] = { 1 };
                uint8_t nonce[12] = { 3 };
                uint8_t aad[1] = { 1 };
                uint8_t pt[8] = { 2 };

                const AssociatedData info[] = {
                        { aad, sizeof(aad) },
                        { nonce, sizeof(nonce) },
                        { NULL }
                };

                uint8_t ct[] = {
                        0x1e,0x6d,0xab,0xa3, 0x56,0x69,0xf4,0x27, 0x3b,0x0a,0x1a,0x25, 0x60,0x96,0x9c,0xdf,
                        0x79,0x0d,0x99,0x75, 0x9a,0xbd,0x15,0x08,
                };

                uint8_t out[sizeof(ct)];

                assert_se(NTS_encrypt(out, pt, sizeof(pt), info, NTS_get_param(NTS_AEAD_AES_128_GCM_SIV), key) == sizeof(ct));
                assert_se(memcmp(out, ct, sizeof(ct)) == 0);
        }
}

TEST(keysize) {
        assert_se(NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256)->key_size == 32);
        assert_se(NTS_get_param(NTS_AEAD_AES_SIV_CMAC_512)->key_size == 64);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
