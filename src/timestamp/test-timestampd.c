/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "fd-util.h"
#include "memfd-util.h"
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

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), &resp));
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

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), &resp));
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

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), &resp));
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

        ASSERT_OK_ZERO(tsp_parse_response(der, sizeof(der), &resp));
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

        ASSERT_ERROR(tsp_parse_response(der, sizeof(der), &resp), EBADMSG);
}

TEST(parse_garbage_response) {
        static const uint8_t garbage[] = { 0x01, 0x02, 0x03, 0x04 };
        _cleanup_(tsp_response_done) TspResponse resp = {};

        ASSERT_ERROR(tsp_parse_response(garbage, sizeof(garbage), &resp), EBADMSG);
        ASSERT_NULL(resp.token_pem);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
