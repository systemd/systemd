/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "openssl-util.h"
#include "tests.h"

TEST(openssl_pkey_from_pem) {
        DEFINE_HEX_PTR(key_ecc, "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145726a6e4575424c73496c3972687068777976584e50686a346a426e500a44586e794a304b395579724e6764365335413532542b6f5376746b436a365a726c34685847337741515558706f426c532b7448717452714c35513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_ecc = NULL;
        assert_se(openssl_pubkey_from_pem(key_ecc, key_ecc_len, &pkey_ecc) >= 0);

        _cleanup_free_ void *x = NULL, *y = NULL;
        size_t x_len, y_len;
        int curve_id;
        assert_se(ecc_pkey_to_curve_x_y(pkey_ecc, &curve_id, &x, &x_len, &y, &y_len) >= 0);
        assert_se(curve_id == NID_X9_62_prime256v1);

        DEFINE_HEX_PTR(expected_x, "ae39c4b812ec225f6b869870caf5cd3e18f88c19cf0d79f22742bd532acd81de");
        assert_se(memcmp_nn(x, x_len, expected_x, expected_x_len) == 0);

        DEFINE_HEX_PTR(expected_y, "92e40e764fea12bed9028fa66b9788571b7c004145e9a01952fad1eab51a8be5");
        assert_se(memcmp_nn(y, y_len, expected_y, expected_y_len) == 0);

        DEFINE_HEX_PTR(key_rsa, "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541795639434950652f505852337a436f63787045300a6a575262546c3568585844436b472f584b79374b6d2f4439584942334b734f5a31436a5937375571372f674359363170697838697552756a73413464503165380a593445336c68556d374a332b6473766b626f4b64553243626d52494c2f6675627771694c4d587a41673342575278747234547545443533527a373634554650640a307a70304b68775231496230444c67772f344e67566f314146763378784b4d6478774d45683567676b73733038326332706c354a504e32587677426f744e6b4d0a5471526c745a4a35355244436170696e7153334577376675646c4e735851357746766c7432377a7637344b585165616d704c59433037584f6761304c676c536b0a79754774586b6a50542f735542544a705374615769674d5a6f714b7479563463515a58436b4a52684459614c47587673504233687a766d5671636e6b47654e540a65774944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_rsa = NULL;
        assert_se(openssl_pubkey_from_pem(key_rsa, key_rsa_len, &pkey_rsa) >= 0);

        _cleanup_free_ void *n = NULL, *e = NULL;
        size_t n_len, e_len;
        assert_se(rsa_pkey_to_n_e(pkey_rsa, &n, &n_len, &e, &e_len) >= 0);

        DEFINE_HEX_PTR(expected_n, "c95f4220f7bf3d7477cc2a1cc691348d645b4e5e615d70c2906fd72b2eca9bf0fd5c80772ac399d428d8efb52aeff80263ad698b1f22b91ba3b00e1d3f57bc638137961526ec9dfe76cbe46e829d53609b99120bfdfb9bc2a88b317cc0837056471b6be13b840f9dd1cfbeb85053ddd33a742a1c11d486f40cb830ff8360568d4016fdf1c4a31dc7030487982092cb34f36736a65e493cdd97bf0068b4d90c4ea465b59279e510c26a98a7a92dc4c3b7ee76536c5d0e7016f96ddbbcefef829741e6a6a4b602d3b5ce81ad0b8254a4cae1ad5e48cf4ffb140532694ad6968a0319a2a2adc95e1c4195c29094610d868b197bec3c1de1cef995a9c9e419e3537b");
        assert_se(memcmp_nn(n, n_len, expected_n, expected_n_len) == 0);

        DEFINE_HEX_PTR(expected_e, "010001");
        assert_se(memcmp_nn(e, e_len, expected_e, expected_e_len) == 0);
}

TEST(rsa_pkey_n_e) {
        DEFINE_HEX_PTR(n, "e3975a2124a7c9fe57752d106314ff62f6da731632eac221f1c0255bdcf2a34eeb21e3ab89ba8759ddad3b68be99463c7f03f3d004028a35e6f7c6596aeab2558d490f1e1c38aed2ff796bda8d6d55704eefb6ac55842dd6e606bb707f66acc02f0db2aed0dabab885bd0c850f1bdc8ac4b6bc1f74858db8ca2ab57a3d4217c091e9cd78727a2e36b8126ea629e81fecc69b0bea601000a6c0b749c5be16f53f4fa9f208a581d804234eb6526ba3fee9822d58d1ab9cac2761d7f630eb7ad6054dff0856d41aea219e1adfd87256aa1532202a070f4b1044e718d1f38bbc5a4b1fcb024f04afaafda5edeacfdf0d0bdf35c359acd059e3edb5024e588458f9b5");
        uint32_t e = htobe32(0x10001);

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        assert_se(rsa_pkey_from_n_e(n, n_len, &e, sizeof(e), &pkey) >= 0);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*) pkey, NULL);
        assert_se(ctx);
        assert_se(EVP_PKEY_verify_init(ctx) == 1);

        const char *msg = "this is a secret";
        DEFINE_HEX_PTR(sig, "14b53e0c6ad99a350c3d7811e8160f4ae03ad159815bb91bddb9735b833588df2eac221fbd3fc4ece0dd63bfaeddfdaf4ae67021e759f3638bc194836413414f54e8c4d01c9c37fa4488ea2ef772276b8a33822a53c97b1c35acfb4bc621cfb8fad88f0cf7d5491f05236886afbf9ed47f9469536482f50f74a20defa59d99676bed62a17b5eb98641df5a2f8080fa4b24f2749cc152fa65ba34c14022fcb27f1b36f52021950d7b9b6c3042c50b84cfb7d55a5f9235bfd58e1bf1f604eb93416c5fb5fd90cb68f1270dfa9daf67f52c604f62c2f2beee5e7e672b0e6e9833dd43dba99b77668540c850c9a81a5ea7aaf6297383e6135bd64572362333121fc7");
        assert_se(EVP_PKEY_verify(ctx, sig, sig_len, (unsigned char*) msg, strlen(msg)) == 1);

        DEFINE_HEX_PTR(invalid_sig, "1234");
        assert_se(EVP_PKEY_verify(ctx, invalid_sig, invalid_sig_len, (unsigned char*) msg, strlen(msg)) != 1);

        _cleanup_free_ void *n2 = NULL, *e2 = NULL;
        size_t n2_size, e2_size;
        assert_se(rsa_pkey_to_n_e(pkey, &n2, &n2_size, &e2, &e2_size) >= 0);
        assert_se(memcmp_nn(n, n_len, n2, n2_size) == 0);
        assert_se(e2_size <= sizeof(uint32_t));
        assert_se(memcmp(&((uint8_t*) &e)[sizeof(uint32_t) - e2_size], e2, e2_size) == 0);
}

TEST(ecc_pkey_curve_x_y) {
        int curveid = NID_X9_62_prime256v1;
        DEFINE_HEX_PTR(x, "2830d2c8f65d3efbef12303b968b91692f8bd04045dcb8a9656374e4ae61d818");
        DEFINE_HEX_PTR(y, "8a80750f76729defdcc2a4bc1a91c22e60109dd6e1ffde634a650a20bab172e9");

        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;
        assert_se(ecc_pkey_from_curve_x_y(curveid, x, x_len, y, y_len, &pkey) >= 0);

        _cleanup_(EVP_PKEY_CTX_freep) EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY*) pkey, NULL);
        assert_se(ctx);
        assert_se(EVP_PKEY_verify_init(ctx) == 1);

        const char *msg = "this is a secret";
        DEFINE_HEX_PTR(sig, "3045022100f6ca10f7ed57a020679899b26dd5ac5a1079265885e2a6477f527b6a3f02b5ca02207b550eb3e7b69360aff977f7f6afac99c3f28266b6c5338ce373f6b59263000a");
        assert_se(EVP_PKEY_verify(ctx, sig, sig_len, (unsigned char*) msg, strlen(msg)) == 1);

        DEFINE_HEX_PTR(invalid_sig, "1234");
        assert_se(EVP_PKEY_verify(ctx, invalid_sig, invalid_sig_len, (unsigned char*) msg, strlen(msg)) != 1);

        _cleanup_free_ void *x2 = NULL, *y2 = NULL;
        size_t x2_size, y2_size;
        int curveid2;
        assert_se(ecc_pkey_to_curve_x_y(pkey, &curveid2, &x2, &x2_size, &y2, &y2_size) >= 0);
        assert_se(curveid == curveid2);
        assert_se(memcmp_nn(x, x_len, x2, x2_size) == 0);
        assert_se(memcmp_nn(y, y_len, y2, y2_size) == 0);
}

TEST(invalid) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey = NULL;

        DEFINE_HEX_PTR(key, "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b7b");
        assert_se(openssl_pubkey_from_pem(key, key_len, &pkey) == -EIO);
        ASSERT_NULL(pkey);
}

static const struct {
        const char *alg;
        size_t size;
} digest_size_table[] = {
        /* SHA1 "family" */
        { "sha1",     20, },
        { "sha-1",    20, },
        /* SHA2 family */
        { "sha224",   28, },
        { "sha256",   32, },
        { "sha384",   48, },
        { "sha512",   64, },
        { "sha-224",  28, },
        { "sha2-224", 28, },
        { "sha-256",  32, },
        { "sha2-256", 32, },
        { "sha-384",  48, },
        { "sha2-384", 48, },
        { "sha-512",  64, },
        { "sha2-512", 64, },
        /* SHA3 family */
        { "sha3-224", 28, },
        { "sha3-256", 32, },
        { "sha3-384", 48, },
        { "sha3-512", 64, },
        /* SM3 family */
        { "sm3",      32, },
        /* MD5 family */
        { "md5",      16, },
};

TEST(digest_size) {
        size_t size;

        FOREACH_ELEMENT(t, digest_size_table) {
                assert(openssl_digest_size(t->alg, &size) >= 0);
                assert_se(size == t->size);

                _cleanup_free_ char *uppercase_alg = strdup(t->alg);
                assert_se(uppercase_alg);
                assert_se(openssl_digest_size(ascii_strupper(uppercase_alg), &size) >= 0);
                assert_se(size == t->size);
        }

        assert_se(openssl_digest_size("invalid.alg", &size) == -EOPNOTSUPP);
}

static void verify_digest(const char *digest_alg, const struct iovec *data, size_t n_data, const char *expect) {
        _cleanup_free_ void *digest = NULL;
        size_t digest_size;
        int r;

        r = openssl_digest_many(digest_alg, data, n_data, &digest, &digest_size);
        if (r == -EOPNOTSUPP)
                return;
        assert_se(r >= 0);

        DEFINE_HEX_PTR(e, expect);
        assert_se(memcmp_nn(e, e_len, digest, digest_size) == 0);
}

#define _DEFINE_DIGEST_TEST(uniq, alg, expect, ...)                     \
        const struct iovec UNIQ_T(i, uniq)[] = { __VA_ARGS__ };         \
        verify_digest(alg,                                              \
                      UNIQ_T(i, uniq),                                  \
                      ELEMENTSOF(UNIQ_T(i, uniq)),                      \
                      expect);
#define DEFINE_DIGEST_TEST(alg, expect, ...) _DEFINE_DIGEST_TEST(UNIQ, alg, expect, __VA_ARGS__)
#define DEFINE_SHA1_TEST(expect, ...) DEFINE_DIGEST_TEST("SHA1", expect, __VA_ARGS__)
#define DEFINE_SHA256_TEST(expect, ...) DEFINE_DIGEST_TEST("SHA256", expect, __VA_ARGS__)
#define DEFINE_SHA384_TEST(expect, ...) DEFINE_DIGEST_TEST("SHA384", expect, __VA_ARGS__)
#define DEFINE_SHA512_TEST(expect, ...) DEFINE_DIGEST_TEST("SHA512", expect, __VA_ARGS__)

TEST(digest_many) {
        const struct iovec test = IOVEC_MAKE_STRING("test");

        /* Empty digests */
        DEFINE_SHA1_TEST("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        DEFINE_SHA256_TEST("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        DEFINE_SHA384_TEST("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        DEFINE_SHA512_TEST("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        DEFINE_SHA1_TEST("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", test);
        DEFINE_SHA256_TEST("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", test);
        DEFINE_SHA384_TEST("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9", test);
        DEFINE_SHA512_TEST("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", test);

        DEFINE_HEX_PTR(h1, "e9ff2b6dfbc03b8dd0471a0f23840334e3ef51c64a325945524563c0375284a092751eca8d084fae22f74a104559a0ee8339d1845538481e674e6d31d4f63089");
        DEFINE_HEX_PTR(h2, "5b6e809933a1b8d5a4a6bb62e20b36ae82d9408141e7479d0aa067273bd2d04007fb1977bad549d54330a49ed98f82b495ba");
        DEFINE_HEX_PTR(h3, "d2aeef94d7ba2a");
        DEFINE_HEX_PTR(h4, "1557db45ded3e38c79b5bb25c83ade42fa7d13047ef1b9a0b21a3c2ab2d4eee5c75e2927ce643163addbda65331035850a436c0acffc723f419e1d1cbf04c9064e6d850580c0732a12600f9feb");

        const struct iovec i1 = IOVEC_MAKE(h1, h1_len);
        const struct iovec i2 = IOVEC_MAKE(h2, h2_len);
        const struct iovec i3 = IOVEC_MAKE(h3, h3_len);
        const struct iovec i4 = IOVEC_MAKE(h4, h4_len);

        DEFINE_SHA1_TEST("8e7c659a6331508b06adf98b430759dafb92fc43", i1, i2, i3, i4);
        DEFINE_SHA256_TEST("4d6be38798786a5500651c1a02d96aa010e9d7b2bece1695294cd396d456cde8", i1, i2, i3, i4);
        DEFINE_SHA384_TEST("82e6ec14f8d90f1ae1fd4fb7f415ea6fdb674515b13092e3e548a8d37a8faed30cda8ea613ec2a015a51bc578dacc995", i1, i2, i3, i4);
        DEFINE_SHA512_TEST("21fe5beb15927257a9143ff59010e51d4c65c7c5237b0cd9a8db3c3fabe429be3a0759f9ace3cdd70f6ea543f998bec9bc3308833d70aa1bd380364de872a62c", i1, i2, i3, i4);

        DEFINE_SHA256_TEST("0e0ed67d6717dc08dd6f472f6c35107a92b8c2695dcba344b884436f97a9eb4d", i1, i1, i1, i4);

        DEFINE_SHA256_TEST("8fe8b8d1899c44bfb82e1edc4ff92642db5b2cb25c4210ea06c3846c757525a8", i1, i1, i1, i4, i4, i4, i4, i3, i3, i2);
}

static void verify_hmac(
                const char *digest_alg,
                const char *key,
                const struct iovec *data,
                size_t n_data,
                const char *expect) {

        DEFINE_HEX_PTR(k, key);
        DEFINE_HEX_PTR(e, expect);
        _cleanup_free_ void *digest = NULL;
        size_t digest_size;

        if (n_data == 0) {
                assert_se(openssl_hmac(digest_alg, k, k_len, NULL, 0, &digest, &digest_size) == 0);
                assert_se(memcmp_nn(e, e_len, digest, digest_size) == 0);
                digest = mfree(digest);
        } else if(n_data == 1) {
                assert_se(openssl_hmac(digest_alg, k, k_len, data[0].iov_base, data[0].iov_len, &digest, &digest_size) == 0);
                assert_se(memcmp_nn(e, e_len, digest, digest_size) == 0);
                digest = mfree(digest);
        }

        assert_se(openssl_hmac_many(digest_alg, k, k_len, data, n_data, &digest, &digest_size) == 0);
        assert_se(memcmp_nn(e, e_len, digest, digest_size) == 0);
}

#define _DEFINE_HMAC_TEST(uniq, alg, key, expect, ...)                  \
        const struct iovec UNIQ_T(i, uniq)[] = { __VA_ARGS__ };         \
        verify_hmac(alg,                                                \
                    key,                                                \
                    UNIQ_T(i, uniq),                                    \
                    ELEMENTSOF(UNIQ_T(i, uniq)),                        \
                    expect);
#define DEFINE_HMAC_TEST(alg, key, expect, ...) _DEFINE_HMAC_TEST(UNIQ, alg, key, expect, __VA_ARGS__)
#define DEFINE_HMAC_SHA1_TEST(key, expect, ...) DEFINE_HMAC_TEST("SHA1", key, expect, __VA_ARGS__)
#define DEFINE_HMAC_SHA256_TEST(key, expect, ...) DEFINE_HMAC_TEST("SHA256", key, expect, __VA_ARGS__)
#define DEFINE_HMAC_SHA384_TEST(key, expect, ...) DEFINE_HMAC_TEST("SHA384", key, expect, __VA_ARGS__)
#define DEFINE_HMAC_SHA512_TEST(key, expect, ...) DEFINE_HMAC_TEST("SHA512", key, expect, __VA_ARGS__)

TEST(hmac_many) {
        const char *key1 = "760eb6845073862c1914c6d188bf8214",
                *key2 = "0628d1a5f83fce99779e12e2336d87046d42d74b755f00d9f72350668860fd00",
                *key3 = "b61158912b76348c54f104629924be4178b8a9c9459c3a6e9daa1885445a61fccc1aa0f749c31f3ade4e227f64dd0e86a94b25c2e181f044af22d0a8c07074c3";
        const struct iovec test = IOVEC_MAKE_STRING("test");

        /* Empty digests */
        DEFINE_HMAC_SHA1_TEST(key1, "EB9725FC9A99A652C3171E0863984AC42461F88B");
        DEFINE_HMAC_SHA256_TEST(key1, "82A15D4DD5F583CF8F06D3E447DF0FDFF95A24E29229934B48BD0A5B4E0ADC85");
        DEFINE_HMAC_SHA384_TEST(key1, "C60F15C4E18736750D91095ADA148C4179825A487CCA3AE047A2FB94F85A5587AB6AF57678AA79715FEF848129C108C3");
        DEFINE_HMAC_SHA512_TEST(key1, "2B10DC9BFC0349400F8965482EA149C1C51C865BB7B16097623F41C14CF6C8A678724BFAE0CE842EED899C12CC17B5D8C4287F72BE788532FE7CF0BE2EBCD447");

        DEFINE_HMAC_SHA1_TEST(key2, "F9AA74F129681E91807EB264EA6E1B5C5F9B4CFD");
        DEFINE_HMAC_SHA256_TEST(key2, "B4ADEBF8B3044A5B0668B742C0A49B61D8380F89938C84794C92567F5A33CC7D");
        DEFINE_HMAC_SHA384_TEST(key2, "E5EACAB7A13CF5BE60FA228D771E183CD6E57536BB9EAFC34A6BB52B1B1324BD6FB8A1713F91EC040790AE97F5672D53");
        DEFINE_HMAC_SHA512_TEST(key2, "75A597D83A6270FC3204DE741E76DEFCF42D3E1812C71E41EEA8C0F23C07315822E83BE8B54705CB00FEF4CE1BAF80E3975414925C83BF3719CEBC27DD133F7D");

        DEFINE_HMAC_SHA1_TEST(key3, "4B8EACB3C3935ACC8C58995C89F16020FC993569");
        DEFINE_HMAC_SHA256_TEST(key3, "520E8C0323A1994D58EF5456611BCB6CD701399B24F8FBA0B5A3CD3186780E8E");
        DEFINE_HMAC_SHA384_TEST(key3, "52ADAF691EFDC377B7349EAA45EE1BFAFA27CAC1FFE08B942C80426D1CA9F3464E3A71D611DA0B415435E82D6EE9F34A");
        DEFINE_HMAC_SHA512_TEST(key3, "22D8C17BAF591E07CD2BD58A1B3D76D5904EC45C9099F0171A243F07611E25208A395833BC3F9BBD425636FD8D574BE1A1A367DCB6C40AD3C06E2B57E8FD2729");

        /* test message */
        DEFINE_HMAC_SHA1_TEST(key2, "DEE6313BE6391523D0B2B326890F13A65F3965B2", test);
        DEFINE_HMAC_SHA256_TEST(key2, "496FF3E9DA52B2B490CD5EAE23457F8A33E61AB7B42F6E6374B7629CFBE1FCED", test);
        DEFINE_HMAC_SHA384_TEST(key2, "F5223F750D671453CA6159C1354242DB13E0189CB79AC73E4964F623181B00C811A596F7CE3408DDE06B96C6D792F41E", test);
        DEFINE_HMAC_SHA512_TEST(key2, "8755A8B0D85D89AFFE7A15702BBA0F835CDE454334EC952ED777A30035D6BD9407EA5DF8DCB89814C1DF7EE215022EA68D9D2BC4E4B299CD6F55CD60C269A706", test);

        DEFINE_HEX_PTR(h1, "e9ff2b6dfbc03b8dd0471a0f23840334e3ef51c64a325945524563c0375284a092751eca8d084fae22f74a104559a0ee8339d1845538481e674e6d31d4f63089");
        DEFINE_HEX_PTR(h2, "5b6e809933a1b8d5a4a6bb62e20b36ae82d9408141e7479d0aa067273bd2d04007fb1977bad549d54330a49ed98f82b495ba");
        DEFINE_HEX_PTR(h3, "d2aeef94d7ba2a");
        DEFINE_HEX_PTR(h4, "1557db45ded3e38c79b5bb25c83ade42fa7d13047ef1b9a0b21a3c2ab2d4eee5c75e2927ce643163addbda65331035850a436c0acffc723f419e1d1cbf04c9064e6d850580c0732a12600f9feb");

        const struct iovec i1 = IOVEC_MAKE(h1, h1_len);
        const struct iovec i2 = IOVEC_MAKE(h2, h2_len);
        const struct iovec i3 = IOVEC_MAKE(h3, h3_len);
        const struct iovec i4 = IOVEC_MAKE(h4, h4_len);

        DEFINE_HMAC_SHA1_TEST(key2, "28C041532012BFF1B7C87B2A15A8C43EB8037D27", i1, i2, i3, i4);
        DEFINE_HMAC_SHA256_TEST(key2, "F8A1FBDEE3CD383EA2B4940A3C8E72F443DB5B247016C9F84E2D2FEF3C5A0A23", i1, i2, i3, i4);
        DEFINE_HMAC_SHA384_TEST(key2, "4D2AB0516F1F5C73BD0761407E0AF42361C1CAE761685FC65D1199598315EE3DCA4DB88E4D96FB06C2DA215A33FA9CE9", i1, i2, i3, i4);
        DEFINE_HMAC_SHA512_TEST(key2, "E9BF8FC6FDE75FD5E4EF2DF399EE675C57B60C59A7B331F30535FDE68D8072185552E9A8BFA2008C52437F1BCC1472D16FBCF2A77C37339752938E42D2642150", i1, i2, i3, i4);

        DEFINE_HMAC_SHA256_TEST(key3, "94D4E4B55368A533F6A7FDCC3B93E1F283BB1CA387BB5D14FAFF44A009EDF040", i1, i1, i1, i4);

        DEFINE_HMAC_SHA256_TEST(key3, "5BE1F4D9C2AFAA2BB3F58FCE967BC7D3084BB8F512659875BDA634991145B0F0", i1, i1, i1, i4, i4, i4, i4, i3, i3, i2);
}

TEST(kdf_kb_hmac_derive) {
        _cleanup_free_ void *derived_key = NULL;

        DEFINE_HEX_PTR(key, "d7ac57124f28371eacaec475b74869d26b4cd64586412a607ce0a9e0c63d468c");
        const char *salt = "salty chocolate";
        DEFINE_HEX_PTR(info, "6721a2012d9554f5a64593ed3eaa8fe15e6a21e1c8c8736ea4d234eb55b9e31a");
        DEFINE_HEX_PTR(expected_derived_key, "A9DA9CEEB9578DBE7DD2862F82898B086E85FF2D10C4E8EC5BD99D0D7F003A2DE1574EB4BD789C03EF5235259BCB3A009DA303EA4DB4CA6BF507DB7C5A063279");

        assert_se(kdf_kb_hmac_derive("COUNTER", "SHA256", key, key_len, salt, strlen(salt), info, info_len, /* seed= */ NULL, /* seed_size= */ 0, 64, &derived_key) >= 0);
        assert_se(memcmp_nn(derived_key, 64, expected_derived_key, expected_derived_key_len) == 0);
}

static void check_ss_derive(const char *hex_key, const char *hex_salt, const char *hex_info, const char *hex_expected) {
        DEFINE_HEX_PTR(key, hex_key);
        DEFINE_HEX_PTR(salt, hex_salt);
        DEFINE_HEX_PTR(info, hex_info);
        DEFINE_HEX_PTR(expected, hex_expected);

        _cleanup_free_ void *derived_key = NULL;
        assert_se(kdf_ss_derive("SHA256", key, key_len, salt, salt_len, info, info_len, expected_len, &derived_key) >= 0);
        assert_se(memcmp_nn(derived_key, expected_len, expected, expected_len) == 0);
}

TEST(kdf_ss_derive) {
        check_ss_derive(
                "01166ad6b05d1fad8cdb50d1902170e9",
                "feea805789dc8d0b57da5d4d61886b1a",
                "af4cb6d1d0a996e21e3788584165e2ae",
                "46CECAB4544E11EF986641BA6F843FAFFD111D3974C34E3B9592311E8579C6BD");

        check_ss_derive(
                "d1c39e37260d79d6e766f1d1412c4b61fc0801db469b97c897b0fbcaebea5178",
                "b75e3b65d1bb845dee581c7e14cfebc6e882946e90273b77ebe289faaf7de248",
                "ed25a0043d6c1eb28296da1f9ab138dafee18f4c937bfc43601d4ee6e7634199",
                "30EB1A1E9DEA7DE4DDB8F3FDF50A01E3");
        /* Same inputs as above, but derive more bytes */
        check_ss_derive(
                "d1c39e37260d79d6e766f1d1412c4b61fc0801db469b97c897b0fbcaebea5178",
                "b75e3b65d1bb845dee581c7e14cfebc6e882946e90273b77ebe289faaf7de248",
                "ed25a0043d6c1eb28296da1f9ab138dafee18f4c937bfc43601d4ee6e7634199",
                "30EB1A1E9DEA7DE4DDB8F3FDF50A01E30581D606C1228D98AFF691DF743AC2EE9D99EFD2AE1946C079AA18C9524877FA65D5065F0DAED058AB3416AF80EB2B73");
}

static void check_cipher(
                const char *alg,
                size_t bits,
                const char *mode,
                const char *hex_key,
                const char *hex_iv,
                const struct iovec data[],
                size_t n_data,
                const char *hex_expected) {

        _cleanup_free_ void *enc_buf = NULL;
        size_t enc_buf_len;

        DEFINE_HEX_PTR(key, hex_key);
        DEFINE_HEX_PTR(iv, hex_iv);
        DEFINE_HEX_PTR(expected, hex_expected);

        if (n_data == 0) {
                assert_se(openssl_cipher(alg, bits, mode, key, key_len, iv, iv_len, NULL, 0, &enc_buf, &enc_buf_len) >= 0);
                assert_se(memcmp_nn(enc_buf, enc_buf_len, expected, expected_len) == 0);
                enc_buf = mfree(enc_buf);
        } else if (n_data == 1) {
                assert_se(openssl_cipher(alg, bits, mode, key, key_len, iv, iv_len, data[0].iov_base, data[0].iov_len, &enc_buf, &enc_buf_len) >= 0);
                assert_se(memcmp_nn(enc_buf, enc_buf_len, expected, expected_len) == 0);
                enc_buf = mfree(enc_buf);
        }

        assert_se(openssl_cipher_many(alg, bits, mode, key, key_len, iv, iv_len, data, n_data, &enc_buf, &enc_buf_len) >= 0);
        assert_se(memcmp_nn(enc_buf, enc_buf_len, expected, expected_len) == 0);
}

TEST(openssl_cipher) {
        struct iovec data[] = {
                IOVEC_MAKE_STRING("my"),
                IOVEC_MAKE_STRING(" "),
                IOVEC_MAKE_STRING("secret"),
                IOVEC_MAKE_STRING(" "),
                IOVEC_MAKE_STRING("text"),
                IOVEC_MAKE_STRING("!"),
        };

        check_cipher(
                "aes", 256, "cfb",
                "32c62bbaeb0decc5c874b8e0148f86475b5bb10a36f7078a75a6f11704c2f06a",
                /* hex_iv= */ NULL,
                data, ELEMENTSOF(data),
                "bd4a46f8762bf4bef4430514aaec5e");

        check_cipher(
                "aes", 256, "cfb",
                "32c62bbaeb0decc5c874b8e0148f86475b5bb10a36f7078a75a6f11704c2f06a",
                "00000000000000000000000000000000",
                data, ELEMENTSOF(data),
                "bd4a46f8762bf4bef4430514aaec5e");

        check_cipher(
                "aes", 256, "cfb",
                "32c62bbaeb0decc5c874b8e0148f86475b5bb10a36f7078a75a6f11704c2f06a",
                "9088fd5c4ad9b9419eced86283021a59",
                data, ELEMENTSOF(data),
                "6dfbf8dc972f9a462ad7427a1fa41a");

        check_cipher(
                "aes", 256, "cfb",
                "32c62bbaeb0decc5c874b8e0148f86475b5bb10a36f7078a75a6f11704c2f06a",
                /* hex_iv= */ NULL,
                &data[2], 1,
                "a35605f9763c");

        check_cipher(
                "aes", 256, "cfb",
                "32c62bbaeb0decc5c874b8e0148f86475b5bb10a36f7078a75a6f11704c2f06a",
                /* hex_iv= */ NULL,
                /* data= */ NULL, /* n_data= */ 0,
                /* hex_expected= */ NULL);

        check_cipher(
                "aes", 128, "cfb",
                "b8fe4b89f6f25dd58cadceb68c99d508",
                /* hex_iv= */ NULL,
                data, ELEMENTSOF(data),
                "9c0fe3abb904ab419d950ae00c93a1");

        check_cipher(
                "aes", 128, "cfb",
                "b8fe4b89f6f25dd58cadceb68c99d508",
                "00000000000000000000000000000000",
                data, ELEMENTSOF(data),
                "9c0fe3abb904ab419d950ae00c93a1");

        check_cipher(
                "aes", 128, "cfb",
                "b8fe4b89f6f25dd58cadceb68c99d508",
                "9088fd5c4ad9b9419eced86283021a59",
                data, ELEMENTSOF(data),
                "e765617aceb1326f5309008c14f4e1");

        check_cipher(
                "aes", 128, "cfb",
                "b8fe4b89f6f25dd58cadceb68c99d508",
                /* hex_iv= */ NULL,
                /* data= */ NULL, /* n_data= */ 0,
                /* hex_expected= */ NULL);

        check_cipher(
                "aes", 128, "cfb",
                "b8fe4b89f6f25dd58cadceb68c99d508",
                "00000000000000000000000000000000",
                /* data= */ NULL, /* n_data= */ 0,
                /* hex_expected= */ NULL);
}

TEST(ecc_ecdh) {
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkeyA = NULL, *pkeyB = NULL, *pkeyC = NULL;
        _cleanup_free_ void *secretAB = NULL, *secretBA = NULL, *secretAC = NULL, *secretCA = NULL;
        size_t secretAB_size, secretBA_size, secretAC_size, secretCA_size;

        assert_se(ecc_pkey_new(NID_X9_62_prime256v1, &pkeyA) >= 0);
        assert_se(ecc_pkey_new(NID_X9_62_prime256v1, &pkeyB) >= 0);
        assert_se(ecc_pkey_new(NID_X9_62_prime256v1, &pkeyC) >= 0);

        assert_se(ecc_ecdh(pkeyA, pkeyB, &secretAB, &secretAB_size) >= 0);
        assert_se(ecc_ecdh(pkeyB, pkeyA, &secretBA, &secretBA_size) >= 0);
        assert_se(ecc_ecdh(pkeyA, pkeyC, &secretAC, &secretAC_size) >= 0);
        assert_se(ecc_ecdh(pkeyC, pkeyA, &secretCA, &secretCA_size) >= 0);

        assert_se(memcmp_nn(secretAB, secretAB_size, secretBA, secretBA_size) == 0);
        assert_se(memcmp_nn(secretAC, secretAC_size, secretCA, secretCA_size) == 0);
        assert_se(memcmp_nn(secretAC, secretAC_size, secretAB, secretAB_size) != 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
