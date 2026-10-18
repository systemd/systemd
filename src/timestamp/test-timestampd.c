/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "memfd-util.h"
#include "string-util.h"
#include "tests.h"
#include "timestampd-tsp.h"

static const uint8_t test_digest[32] = { 0xde, 0xad, 0xbe, 0xef, };

/* Builds a request and decodes it again, so that the tests below can look at what actually
 * goes out on the wire. */
static TS_REQ* build_and_parse_request(int nid, bool nonce, bool cert_req) {
        _cleanup_free_ void *der = NULL;
        size_t der_size;

        ASSERT_OK(dlopen_libcrypto(LOG_DEBUG));
        ASSERT_OK_ZERO(tsp_build_request(nid, test_digest, sizeof(test_digest), nonce, cert_req, &der, &der_size));

        const unsigned char *p = der;
        TS_REQ *req = sym_d2i_TS_REQ(NULL, &p, der_size);
        ASSERT_NOT_NULL(req);

        /* Whatever we produced must be exactly one TimeStampReq, with nothing left over. */
        ASSERT_EQ((size_t) (p - (const unsigned char*) der), der_size);

        return req;
}

TEST(hash_algorithm_from_string) {
        int nid;
        size_t size;

        /* A missing algorithm defaults to SHA256. */
        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string(NULL, &nid, &size));
        ASSERT_EQ(size, 32U);

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA1", &nid, &size));
        ASSERT_EQ(size, 20U);
        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA256", &nid, &size));
        ASSERT_EQ(size, 32U);
        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA384", &nid, &size));
        ASSERT_EQ(size, 48U);
        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA512", &nid, &size));
        ASSERT_EQ(size, 64U);

        ASSERT_ERROR(tsp_hash_algorithm_from_string("MD5", &nid, &size), EOPNOTSUPP);
        ASSERT_ERROR(tsp_hash_algorithm_from_string("sha256", &nid, &size), EOPNOTSUPP);
}

TEST(digest_fd) {
        static const char test_str[] = "The quick brown fox jumps over the lazy dog";
        int nid;

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA256", &nid, /* ret_digest_size= */ NULL));

        _cleanup_close_ int fd = memfd_new_and_seal("test_str", test_str, strlen(test_str));
        ASSERT_OK(fd);

        _cleanup_free_ void *digest = NULL;
        size_t digest_size;
        ASSERT_OK_ZERO(tsp_digest_fd(nid, fd, &digest, &digest_size));

        DEFINE_HEX_PTR(expected, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
        ASSERT_EQ(digest_size, expected_len);
        ASSERT_EQ(memcmp(digest, expected, expected_len), 0);

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA1", &nid, /* ret_digest_size= */ NULL));

        _cleanup_free_ void *sha1 = NULL;
        size_t sha1_size;
        ASSERT_OK_ZERO(tsp_digest_fd(nid, fd, &sha1, &sha1_size));

        DEFINE_HEX_PTR(expected_sha1, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        ASSERT_EQ(sha1_size, expected_sha1_len);
        ASSERT_EQ(memcmp(sha1, expected_sha1, expected_sha1_len), 0);
}

TEST(digest_fd_empty) {
        int nid;

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA256", &nid, /* ret_digest_size= */ NULL));

        _cleanup_close_ int fd = memfd_new_and_seal("empty", /* data= */ NULL, 0);
        ASSERT_OK(fd);

        _cleanup_free_ void *digest = NULL;
        size_t digest_size;
        ASSERT_OK_ZERO(tsp_digest_fd(nid, fd, &digest, &digest_size));

        DEFINE_HEX_PTR(expected, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        ASSERT_EQ(digest_size, expected_len);
        ASSERT_EQ(memcmp(digest, expected, expected_len), 0);
}

TEST(digest_fd_multiple_chunks) {
        /* More than the read buffer, so that the update loop runs several times. */
        static const size_t size = 300U*U64_KB;
        int nid;

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA512", &nid, /* ret_digest_size= */ NULL));

        _cleanup_free_ uint8_t *data = malloc(size);
        ASSERT_NOT_NULL(data);
        for (size_t i = 0; i < size; i++)
                data[i] = (uint8_t) (i * 7 + (i >> 8));

        _cleanup_close_ int fd = memfd_new_and_seal("chunks", data, size);
        ASSERT_OK(fd);

        _cleanup_free_ void *streamed = NULL;
        size_t streamed_size;
        ASSERT_OK_ZERO(tsp_digest_fd(nid, fd, &streamed, &streamed_size));

        _cleanup_free_ void *one_shot = NULL;
        size_t one_shot_size;
        ASSERT_OK(openssl_digest("SHA512", data, size, &one_shot, &one_shot_size));

        ASSERT_EQ(streamed_size, one_shot_size);
        ASSERT_EQ(memcmp(streamed, one_shot, one_shot_size), 0);
}

TEST(build_request) {
        static const char* const algorithms[] = { "SHA1", "SHA256", "SHA384", "SHA512" };
        static const bool bools[] = { true, false };

        FOREACH_ELEMENT(algorithm, algorithms) {
                int nid;
                size_t digest_size;

                ASSERT_OK_ZERO(tsp_hash_algorithm_from_string(*algorithm, &nid, &digest_size));

                FOREACH_ELEMENT(want_nonce, bools)
                        FOREACH_ELEMENT(want_cert, bools) {
                                _cleanup_(TS_REQ_freep) TS_REQ *req = build_and_parse_request(nid, *want_nonce, *want_cert);

                                /* RFC 3161 pins the version at 1. */
                                ASSERT_EQ(sym_TS_REQ_get_version(req), 1L);

                                TS_MSG_IMPRINT *imprint = sym_TS_REQ_get_msg_imprint(req);
                                ASSERT_NOT_NULL(imprint);

                                /* The imprint names the algorithm we asked for... */
                                X509_ALGOR *algo = sym_TS_MSG_IMPRINT_get_algo(imprint);
                                ASSERT_NOT_NULL(algo);

                                const ASN1_OBJECT *oid;
                                int ptype;
                                const void *pval;
                                sym_X509_ALGOR_get0(&oid, &ptype, &pval, algo);
                                ASSERT_EQ(sym_OBJ_obj2nid(oid), nid);
                                ASSERT_EQ(ptype, V_ASN1_NULL);

                                /* ... and carries the digest we handed over. */
                                ASN1_OCTET_STRING *msg = sym_TS_MSG_IMPRINT_get_msg(imprint);
                                ASSERT_NOT_NULL(msg);
                                ASSERT_EQ((size_t) sym_ASN1_STRING_length(msg), sizeof(test_digest));
                                ASSERT_EQ(memcmp(sym_ASN1_STRING_get0_data(msg), test_digest, sizeof(test_digest)), 0);

                                ASSERT_EQ(sym_TS_REQ_get_cert_req(req), (int) *want_cert);

                                const ASN1_INTEGER *nonce = sym_TS_REQ_get_nonce(req);
                                if (!*want_nonce) {
                                        ASSERT_NULL(nonce);
                                        continue;
                                }

                                ASSERT_NOT_NULL(nonce);
                                ASSERT_EQ(sym_ASN1_STRING_length(nonce), 16);
                        }
        }
}

TEST(build_request_nonce_varies) {
        int nid;

        ASSERT_OK_ZERO(tsp_hash_algorithm_from_string("SHA256", &nid, /* ret_digest_size= */ NULL));

        _cleanup_(TS_REQ_freep) TS_REQ *first = build_and_parse_request(nid, /* nonce= */ true, /* cert_req= */ true);
        _cleanup_(TS_REQ_freep) TS_REQ *second = build_and_parse_request(nid, /* nonce= */ true, /* cert_req= */ true);

        const ASN1_INTEGER *a = sym_TS_REQ_get_nonce(first), *b = sym_TS_REQ_get_nonce(second);
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        ASSERT_EQ(sym_ASN1_STRING_length(a), sym_ASN1_STRING_length(b));
        ASSERT_NE(memcmp(sym_ASN1_STRING_get0_data(a), sym_ASN1_STRING_get0_data(b), sym_ASN1_STRING_length(a)), 0);
}

/* The responses below are hand-encoded: OpenSSL offers no way to build a rejection. */

TEST(parse_response_rejection) {
        static const uint8_t der[] = {
                0x30, 0x19,                                        /* TimeStampResp SEQUENCE */
                  0x30, 0x17,                                      /* PKIStatusInfo SEQUENCE */
                    0x02, 0x01, 0x02,                              /* status INTEGER 2, rejection */
                    0x30, 0x0b,                                    /* statusString SEQUENCE OF */
                      0x0c, 0x09, 'b','a','d',' ','s','t','u','f','f',
                    0x03, 0x05, 0x06, 0x80, 0x00, 0x00, 0x40,      /* failInfo: badAlg(0), systemFailure(25) */
        };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), /* request_der= */ NULL, 0, &resp));
        ASSERT_EQ(resp.status, 2);
        ASSERT_STREQ(resp.status_string, "bad stuff");
        ASSERT_EQ(resp.n_failure_info, 2U);
        ASSERT_EQ(resp.failure_info[0], 0);
        ASSERT_EQ(resp.failure_info[1], 25);
        ASSERT_NULL(resp.token_pem);
}

TEST(parse_response_status_only) {
        static const uint8_t der[] = {
                0x30, 0x05,           /* TimeStampResp SEQUENCE */
                  0x30, 0x03,         /* PKIStatusInfo SEQUENCE */
                    0x02, 0x01, 0x02, /* status INTEGER 2, rejection */
        };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), /* request_der= */ NULL, 0, &resp));
        ASSERT_EQ(resp.status, 2);
        ASSERT_NULL(resp.status_string);
        ASSERT_EQ(resp.n_failure_info, 0U);
        ASSERT_NULL(resp.failure_info);
        ASSERT_NULL(resp.token_pem);
}

TEST(parse_response_status_string_is_joined) {
        /* PKIFreeText is a SEQUENCE OF UTF8String, and we hand the caller one string. */
        static const uint8_t der[] = {
                0x30, 0x0d,            /* TimeStampResp SEQUENCE */
                  0x30, 0x0b,          /* PKIStatusInfo SEQUENCE */
                    0x02, 0x01, 0x02,  /* status INTEGER 2, rejection */
                    0x30, 0x06,        /* statusString SEQUENCE OF */
                      0x0c, 0x01, 'a',
                      0x0c, 0x01, 'b',
        };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), /* request_der= */ NULL, 0, &resp));
        ASSERT_STREQ(resp.status_string, "a b");
}

TEST(parse_response_unknown_failure_bit) {
        /* RFC 3161 assigns no meaning to bit 30, but we report it rather than drop it. */
        static const uint8_t der[] = {
                0x30, 0x0c,                                   /* TimeStampResp SEQUENCE */
                  0x30, 0x0a,                                 /* PKIStatusInfo SEQUENCE */
                    0x02, 0x01, 0x02,                         /* status INTEGER 2, rejection */
                    0x03, 0x05, 0x01, 0x00, 0x00, 0x00, 0x02, /* failInfo BIT STRING, bit 30 set */
        };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), /* request_der= */ NULL, 0, &resp));
        ASSERT_EQ(resp.n_failure_info, 1U);
        ASSERT_EQ(resp.failure_info[0], 30);
}

TEST(parse_response_granted_without_token) {
        static const uint8_t der[] = {
                0x30, 0x05,           /* TimeStampResp SEQUENCE */
                  0x30, 0x03,         /* PKIStatusInfo SEQUENCE */
                    0x02, 0x01, 0x00, /* status INTEGER 0, granted */
        };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_ERROR(tsp_parse_response(der, sizeof(der), /* request_der= */ NULL, 0, &resp), EBADMSG);
}

/* These tests contain genuine granted responses and the requests they do and do not belong to, generated with
 * openssl-ts(1) against a throwaway key. */

TEST(parse_response_granted) {
        /* Matching nonce and message imprint. */
        DEFINE_HEX_PTR(response_nonce_a, "308202b03003020100308202a706092a864886f70d010702a082029830820294020103310f300d060960864801650304020105003072060b2a864886f70d0109100104a0630461305f02010106042a0304013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020103180f32303236303932313231323833345a3003020101020845c0b398737e155d31820208308202040201013036301e311c301a06035504030c1374696d657374616d7064207465737420545341021415d4d6fa1d70b70eb29bc8ba118da005e7e18853300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3236303932313231323833345a302f06092a864886f70d01090431220420f773c3a2959646143562799f6f5f67583d11fbe1dbad6340504ff6fb9dabf0aa3037060b2a864886f70d010910022f31283026302430220420a82c8e674b90c9dbe029e38267cf9764ba5cf501809c923dc398fdd4c44052eb300d06092a864886f70d010101050004820100868e1bc29ca0c6a8d07b341fef04fc5deb9014c7e4f5cc9f171b677f5a4862777b8613fba36ee05e61a560dedb129eb018f5e4cd8491695b65031e30b1c34d1d49f0946b4b6b1ad9c3f0ab7ca7a1f3830e3e22370accd66cd8aaea8797fdc00d6ceac147b72ccb9765ff2932b149625d24e16e4a9023ee6787d3c92cc85b75ccf7387a14df2958dcaf51d8482559cfd276c9b8a5e42c6e42d4318db2fdfa90e1eaf95d10881ac8fdeee9dd94c916f970f5099ec671e54792648872f9c9bf528ae0695d4e6df4186ce1baffaa0fb4ff63a77fa7c286fe9a1ca5e25ca411485d4f283965f47de7aecc969e434f1c0951a83b00b9cb0261bffd511f759297681150");
        DEFINE_HEX_PTR(request_nonce_a, "30400201013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020845c0b398737e155d");

        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(response_nonce_a, response_nonce_a_len,
                                          request_nonce_a, request_nonce_a_len, &resp));
        ASSERT_EQ(resp.status, 0);
        ASSERT_NULL(resp.status_string);
        ASSERT_EQ(resp.n_failure_info, 0U);
        ASSERT_NOT_NULL(resp.token_pem);
        ASSERT_TRUE(startswith(resp.token_pem, "-----BEGIN PKCS7-----"));
}

TEST(parse_response_nonce_mismatch) {
        /* Same message imprint, but this request carries a different nonce. */
        DEFINE_HEX_PTR(response_nonce_a, "308202b03003020100308202a706092a864886f70d010702a082029830820294020103310f300d060960864801650304020105003072060b2a864886f70d0109100104a0630461305f02010106042a0304013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020103180f32303236303932313231323833345a3003020101020845c0b398737e155d31820208308202040201013036301e311c301a06035504030c1374696d657374616d7064207465737420545341021415d4d6fa1d70b70eb29bc8ba118da005e7e18853300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3236303932313231323833345a302f06092a864886f70d01090431220420f773c3a2959646143562799f6f5f67583d11fbe1dbad6340504ff6fb9dabf0aa3037060b2a864886f70d010910022f31283026302430220420a82c8e674b90c9dbe029e38267cf9764ba5cf501809c923dc398fdd4c44052eb300d06092a864886f70d010101050004820100868e1bc29ca0c6a8d07b341fef04fc5deb9014c7e4f5cc9f171b677f5a4862777b8613fba36ee05e61a560dedb129eb018f5e4cd8491695b65031e30b1c34d1d49f0946b4b6b1ad9c3f0ab7ca7a1f3830e3e22370accd66cd8aaea8797fdc00d6ceac147b72ccb9765ff2932b149625d24e16e4a9023ee6787d3c92cc85b75ccf7387a14df2958dcaf51d8482559cfd276c9b8a5e42c6e42d4318db2fdfa90e1eaf95d10881ac8fdeee9dd94c916f970f5099ec671e54792648872f9c9bf528ae0695d4e6df4186ce1baffaa0fb4ff63a77fa7c286fe9a1ca5e25ca411485d4f283965f47de7aecc969e434f1c0951a83b00b9cb0261bffd511f759297681150");
        DEFINE_HEX_PTR(request_nonce_b, "30400201013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020866ef23c8c8822bd7");

        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_ERROR(tsp_parse_response(response_nonce_a, response_nonce_a_len,
                                        request_nonce_b, request_nonce_b_len, &resp), EBADMSG);
        ASSERT_NULL(resp.token_pem);
}

TEST(parse_response_without_nonce) {
        /* Neither side carries a nonce, but the message imprint is the same. */
        DEFINE_HEX_PTR(response_plain_d, "308202a630030201003082029d06092a864886f70d010702a082028e3082028a020103310f300d060960864801650304020105003068060b2a864886f70d0109100104a0590457305502010106042a0304013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020104180f32303236303932313231323833345a300302010131820208308202040201013036301e311c301a06035504030c1374696d657374616d7064207465737420545341021415d4d6fa1d70b70eb29bc8ba118da005e7e18853300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3236303932313231323833345a302f06092a864886f70d010904312204202df314a1804b39aa400dce4b9a70c92e46d2ae8680eb1eb3ca04347af5696b0c3037060b2a864886f70d010910022f31283026302430220420a82c8e674b90c9dbe029e38267cf9764ba5cf501809c923dc398fdd4c44052eb300d06092a864886f70d010101050004820100726d7e730c858c8cd4bc6c28ae2cdc40555b742f2d8213b2272758378fe1a344f28c0bd39fb8fff3ceff7baf3ad7199db7a65918c9ff180e7f0a54fa98224975dd3d5bb87688d6f9a72eb5a52cf93a9f6e3819f2c7b487baaff936e4353748c687eae973bee7b29c97f64244fbd6bae267b7caff8262ccc75c5b5416e7f5b374324e6bccf28e072c80ea06a1f3ef20763f53b50f006c26bc4af79fc7745ee3218023ddf2f068b7951729697024d4f2e99fe6d7375475431285bfae51103fbaf639183538e9c0c1450b552d6d80d63a6ca301c4aa632cd4799a81447211f160e7d911a1d23b8b71480bc5b4d6f36b3a620b9b396f2cccd3ccb977a6089bc1b385");
        DEFINE_HEX_PTR(request_plain_d, "30360201013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd");

        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_OK_ZERO(tsp_parse_response(response_plain_d, response_plain_d_len,
                                          request_plain_d, request_plain_d_len, &resp));
        ASSERT_NOT_NULL(resp.token_pem);
}

TEST(parse_response_imprint_mismatch) {
        /* No nonce on either side, and the message imprint is different. */
        DEFINE_HEX_PTR(response_plain_d, "308202a630030201003082029d06092a864886f70d010702a082028e3082028a020103310f300d060960864801650304020105003068060b2a864886f70d0109100104a0590457305502010106042a0304013031300d0609608648016503040201050004205264131d31510d763bf6a68e593af96a6b60e233ca52352600d5ebaba41174dd020104180f32303236303932313231323833345a300302010131820208308202040201013036301e311c301a06035504030c1374696d657374616d7064207465737420545341021415d4d6fa1d70b70eb29bc8ba118da005e7e18853300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3236303932313231323833345a302f06092a864886f70d010904312204202df314a1804b39aa400dce4b9a70c92e46d2ae8680eb1eb3ca04347af5696b0c3037060b2a864886f70d010910022f31283026302430220420a82c8e674b90c9dbe029e38267cf9764ba5cf501809c923dc398fdd4c44052eb300d06092a864886f70d010101050004820100726d7e730c858c8cd4bc6c28ae2cdc40555b742f2d8213b2272758378fe1a344f28c0bd39fb8fff3ceff7baf3ad7199db7a65918c9ff180e7f0a54fa98224975dd3d5bb87688d6f9a72eb5a52cf93a9f6e3819f2c7b487baaff936e4353748c687eae973bee7b29c97f64244fbd6bae267b7caff8262ccc75c5b5416e7f5b374324e6bccf28e072c80ea06a1f3ef20763f53b50f006c26bc4af79fc7745ee3218023ddf2f068b7951729697024d4f2e99fe6d7375475431285bfae51103fbaf639183538e9c0c1450b552d6d80d63a6ca301c4aa632cd4799a81447211f160e7d911a1d23b8b71480bc5b4d6f36b3a620b9b396f2cccd3ccb977a6089bc1b385");
        DEFINE_HEX_PTR(request_plain_e, "30360201013031300d060960864801650304020105000420608a068b33d18be838bcb07bed01e35521d30840fa24db09192e67bfd186e621");

        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_ERROR(tsp_parse_response(response_plain_d, response_plain_d_len,
                                        request_plain_e, request_plain_e_len, &resp), EBADMSG);
        ASSERT_NULL(resp.token_pem);
}

TEST(parse_garbage_response) {
        static const uint8_t garbage[] = { 0x01, 0x02, 0x03, 0x04 };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_ERROR(tsp_parse_response(garbage, sizeof(garbage), /* request_der= */ NULL, 0, &resp), EBADMSG);
        ASSERT_NULL(resp.token_pem);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
