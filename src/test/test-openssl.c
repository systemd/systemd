/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "openssl-util.h"
#include "tests.h"

TEST(openssl_pkey_from_pem) {
        DEFINE_HEX_PTR(key_ecc, "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145726a6e4575424c73496c3972687068777976584e50686a346a426e500a44586e794a304b395579724e6764365335413532542b6f5376746b436a365a726c34685847337741515558706f426c532b7448717452714c35513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_ecc = NULL;
        assert_se(openssl_pkey_from_pem(key_ecc, key_ecc_len, &pkey_ecc) >= 0);

        _cleanup_free_ void *x = NULL, *y = NULL;
        size_t x_len, y_len;
        int curve_id;
        assert_se(ecc_pkey_to_curve_x_y(pkey_ecc, &curve_id, &x, &x_len, &y, &y_len) >= 0);
        assert_se(curve_id == NID_X9_62_prime256v1);

        DEFINE_HEX_PTR(expected_x, "ae39c4b812ec225f6b869870caf5cd3e18f88c19cf0d79f22742bd532acd81de");
        assert_se(x_len == expected_x_len);
        assert_se(memcmp(x, expected_x, x_len) == 0);

        DEFINE_HEX_PTR(expected_y, "92e40e764fea12bed9028fa66b9788571b7c004145e9a01952fad1eab51a8be5");
        assert_se(y_len == expected_y_len);
        assert_se(memcmp(y, expected_y, y_len) == 0);

        DEFINE_HEX_PTR(key_rsa, "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b4341514541795639434950652f505852337a436f63787045300a6a575262546c3568585844436b472f584b79374b6d2f4439584942334b734f5a31436a5937375571372f674359363170697838697552756a73413464503165380a593445336c68556d374a332b6473766b626f4b64553243626d52494c2f6675627771694c4d587a41673342575278747234547545443533527a373634554650640a307a70304b68775231496230444c67772f344e67566f314146763378784b4d6478774d45683567676b73733038326332706c354a504e32587677426f744e6b4d0a5471526c745a4a35355244436170696e7153334577376675646c4e735851357746766c7432377a7637344b585165616d704c59433037584f6761304c676c536b0a79754774586b6a50542f735542544a705374615769674d5a6f714b7479563463515a58436b4a52684459614c47587673504233687a766d5671636e6b47654e540a65774944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a");
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *pkey_rsa = NULL;
        assert_se(openssl_pkey_from_pem(key_rsa, key_rsa_len, &pkey_rsa) >= 0);

        _cleanup_free_ void *n = NULL, *e = NULL;
        size_t n_len, e_len;
        assert_se(rsa_pkey_to_n_e(pkey_rsa, &n, &n_len, &e, &e_len) >= 0);

        DEFINE_HEX_PTR(expected_n, "c95f4220f7bf3d7477cc2a1cc691348d645b4e5e615d70c2906fd72b2eca9bf0fd5c80772ac399d428d8efb52aeff80263ad698b1f22b91ba3b00e1d3f57bc638137961526ec9dfe76cbe46e829d53609b99120bfdfb9bc2a88b317cc0837056471b6be13b840f9dd1cfbeb85053ddd33a742a1c11d486f40cb830ff8360568d4016fdf1c4a31dc7030487982092cb34f36736a65e493cdd97bf0068b4d90c4ea465b59279e510c26a98a7a92dc4c3b7ee76536c5d0e7016f96ddbbcefef829741e6a6a4b602d3b5ce81ad0b8254a4cae1ad5e48cf4ffb140532694ad6968a0319a2a2adc95e1c4195c29094610d868b197bec3c1de1cef995a9c9e419e3537b");
        assert_se(n_len == expected_n_len);
        assert_se(memcmp(n, expected_n, n_len) == 0);

        DEFINE_HEX_PTR(expected_e, "010001");
        assert_se(e_len == expected_e_len);
        assert_se(memcmp(e, expected_e, e_len) == 0);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
