/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "crypto-util.h"
#include "log.h"
#include "random-util.h"
#include "string-util.h"
#include "timestampd-tsp.h"
#include "utf8.h"

/* RFC 3161 suggests a nonce size of at least 64 bits, but that recommendation is from
 * 2001. Use 128 bits here instead. Note that openssl-ts does use 64 bits, but I don't
 * think there's a downside to ignoring that. */
#define NONCE_SIZE_BYTES 16U

void tsp_response_done(TspResponse *r) {
        assert(r);

        r->status_string = mfree(r->status_string);
        r->failure_info = mfree(r->failure_info);
        r->n_failure_info = 0;
        r->token_pem = mfree(r->token_pem);
}

/* Map a digest algorithm name (as accepted by the Varlink interface, e.g. "SHA256") to the corresponding
 * OpenSSL NID and the expected digest length in bytes. A NULL name selects the SHA256 default. Returns
 * -EOPNOTSUPP for unknown algorithms. */
static const struct {
        const char *name;
        int nid;
        size_t size;
} hash_algorithm_table[] = {
        { "SHA1",   NID_sha1,   SHA_DIGEST_LENGTH    },
        { "SHA256", NID_sha256, SHA256_DIGEST_LENGTH },
        { "SHA384", NID_sha384, SHA384_DIGEST_LENGTH },
        { "SHA512", NID_sha512, SHA512_DIGEST_LENGTH },
};

int tsp_hash_algorithm_from_string(const char *name, int *ret_nid, size_t *ret_digest_size) {
        /* A missing algorithm defaults to SHA256, matching the Varlink interface documentation. */
        if (!name)
                name = "SHA256";

        FOREACH_ELEMENT(i, hash_algorithm_table)
                if (streq(name, i->name)) {
                        if (ret_nid)
                                *ret_nid = i->nid;
                        if (ret_digest_size)
                                *ret_digest_size = i->size;
                        return 0;
                }

        return -EOPNOTSUPP;
}

/* The names in the table double as the names OpenSSL knows these digests by. */
static const char* hash_algorithm_to_string(int nid) {
        FOREACH_ELEMENT(i, hash_algorithm_table)
                if (i->nid == nid)
                        return i->name;

        return NULL;
}

/* Digests the whole contents of fd (which must refer to a regular file) with the
 * given algorithm. Reads from offset zero without disturbing the file offset the
 * caller gave us. */
int tsp_digest_fd(int md_nid, int fd, void **ret, size_t *ret_size) {
        assert(fd >= 0);
        assert(ret);
        assert(ret_size);

#if HAVE_OPENSSL
        int r;

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        const char *name = hash_algorithm_to_string(md_nid);
        if (!name)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unknown digest algorithm.");

        const EVP_MD *md = sym_EVP_get_digestbyname(name);
        if (!md)
                return log_openssl_errors(LOG_ERR, "Failed to look up %s implementation.", name);

        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *ctx = sym_EVP_MD_CTX_new();
        if (!ctx)
                return log_oom();

        if (sym_EVP_DigestInit_ex(ctx, md, /* impl= */ NULL) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to initialize %s context.", name);

        for (off_t offset = 0;;) {
                uint8_t buf[64U*U64_KB];

                ssize_t n = pread(fd, buf, sizeof(buf), offset);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        return log_error_errno(errno, "Failed to read data to digest: %m");
                }
                if (n == 0) /* EOF */
                        break;

                if (sym_EVP_DigestUpdate(ctx, buf, n) != 1)
                        return log_openssl_errors(LOG_ERR, "Failed to update %s context.", name);

                offset += n;
        }

        _cleanup_free_ void *digest = malloc(EVP_MAX_MD_SIZE);
        if (!digest)
                return log_oom();

        unsigned size;
        if (sym_EVP_DigestFinal_ex(ctx, digest, &size) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to finalize %s context.", name);

        *ret = TAKE_PTR(digest);
        *ret_size = size;
        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Digests are not supported without OpenSSL.");
#endif
}

/* Build a DER-encoded TimeStampReq. Returns a newly allocated buffer. */
int tsp_build_request(
                int md_nid,
                const void *digest,
                size_t digest_size,
                bool nonce,
                bool cert_req,
                void **ret,
                size_t *ret_size) {

        int r;

        assert(digest || digest_size == 0);
        assert(ret);
        assert(ret_size);

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        _cleanup_(TS_REQ_freep) TS_REQ *req = sym_TS_REQ_new();
        if (!req)
                return log_oom();

        if (sym_TS_REQ_set_version(req, 1) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to set timestamp request version.");

        _cleanup_(TS_MSG_IMPRINT_freep) TS_MSG_IMPRINT *imprint = sym_TS_MSG_IMPRINT_new();
        if (!imprint)
                return log_oom();

        _cleanup_(X509_ALGOR_freep) X509_ALGOR *algo = sym_X509_ALGOR_new();
        if (!algo)
                return log_oom();

        /* Set the message-imprint algorithm identifier to the requested hash. Digest algorithms
         * have no parameters. */
        if (sym_X509_ALGOR_set0(algo, sym_OBJ_nid2obj(md_nid), V_ASN1_NULL, NULL) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to set timestamp request message imprint algorithm.");

        if (sym_TS_MSG_IMPRINT_set_algo(imprint, algo) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to attach algorithm to timestamp request message imprint.");

        if (sym_TS_MSG_IMPRINT_set_msg(imprint, (unsigned char*) digest, (int) digest_size) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to set timestamp request message imprint digest.");

        if (sym_TS_REQ_set_msg_imprint(req, imprint) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to set message imprint on timestamp request.");

        if (cert_req && sym_TS_REQ_set_cert_req(req, 1) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to set timestamp request certReq flag.");

        if (nonce) {
                _cleanup_(ASN1_INTEGER_freep) ASN1_INTEGER *n = sym_ASN1_INTEGER_new();
                if (!n)
                        return log_oom();

                uint8_t buf[NONCE_SIZE_BYTES];

                /* The nonce is encoded as an ASN.1 INTEGER, which is a signed (two's complement)
                 * big-endian type. Positive integers can't have leading zero bytes, although a positive
                 * integer with the high bit set does need a leading zero byte. Note that openssl
                 * encodes the sign in the type of ASN1_INTEGER, so the number we generate here is just
                 * the unsigned magnitude. Openssl will encode a positive integer with the high bit set
                 * correctly - we just need to avoid creating an integer with leading zero bytes. */
                do
                        random_bytes(buf, sizeof(buf));
                while (buf[0] == 0);

                if (sym_ASN1_STRING_set(n, buf, sizeof(buf)) != 1)
                        return log_openssl_errors(LOG_ERR, "Failed to set timestamp request nonce.");

                if (sym_TS_REQ_set_nonce(req, n) != 1)
                        return log_openssl_errors(LOG_ERR, "Failed to attach nonce to timestamp request.");
        }

        int len = sym_i2d_TS_REQ(req, NULL);
        if (len <= 0)
                return log_openssl_errors(LOG_ERR, "Failed to determine timestamp request size.");

        _cleanup_free_ void *der = malloc(len);
        if (!der)
                return log_oom();

        unsigned char *p = der;
        if (sym_i2d_TS_REQ(req, &p) != len)
                return log_openssl_errors(LOG_ERR, "Failed to DER-encode timestamp request.");

        *ret = TAKE_PTR(der);
        *ret_size = len;
        return 0;
}

/* Parse the optional status.statusString field of a TimeStampResp. Returns a newly allocated string, or
 * NULL if the field was not present. */
static int parse_status_string(TS_STATUS_INFO *si, char **ret) {
        _cleanup_free_ char *joined = NULL;

        assert(si);
        assert(ret);

        const STACK_OF(ASN1_UTF8STRING) *text = sym_TS_STATUS_INFO_get0_text(si);
        if (!text) {
                *ret = NULL;
                return 0;
        }

        for (int i = 0; i < sym_sk_ASN1_UTF8STRING_num(text); i++) {
                const ASN1_UTF8STRING *u = sym_sk_ASN1_UTF8STRING_value(text, i);
                if (!u)
                        continue;

                int l = sym_ASN1_STRING_length(u);
                if (l <= 0)
                        continue;

                _cleanup_free_ char *s = memdup_suffix0(sym_ASN1_STRING_get0_data(u), l);
                if (!s)
                        return log_oom();

                _cleanup_free_ char *escaped = utf8_escape_invalid(s);
                if (!escaped)
                        return log_oom();

                if (!strextend_with_separator(&joined, " ", escaped))
                        return log_oom();
        }

        *ret = TAKE_PTR(joined);
        return 0;
}

/* Parse the optional status.failInfo field of a TimeStampResp. Returns a newly allocated array of the bit
 * numbers that are set, empty if the field was not present. */
static int parse_failure_info(TS_STATUS_INFO *si, int **ret, size_t *ret_n) {
        _cleanup_free_ int *bits = NULL;
        size_t n = 0;

        assert(si);
        assert(ret);
        assert(ret_n);

        const ASN1_BIT_STRING *fi = sym_TS_STATUS_INFO_get0_failure_info(si);
        if (!fi) {
                *ret = NULL;
                *ret_n = 0;
                return 0;
        }

        for (int bit = 0; bit < sym_ASN1_STRING_length(fi) * 8; bit++) {
                if (!sym_ASN1_BIT_STRING_get_bit(fi, bit))
                        continue;

                /* RFC 3161 says clients MUST generate an error if values it does not understand
                 * are present. However, we're already generating an error if this field exists,
                 * so it's still useful to report bits that RFC 3161 gives no meaning to. */
                if (!GREEDY_REALLOC(bits, n + 1))
                        return log_oom();

                bits[n++] = bit;
        }

        *ret = TAKE_PTR(bits);
        *ret_n = n;
        return 0;
}

/* RFC 3161 section 2.4.1: if we sent a nonce "the same nonce value MUST be included in the response,
 * otherwise the response shall be rejected". Only we can check the nonce, because the request nonce
 * never leaves the daemon. While we are at it, confirm the token contains the digest we asked to have
 * time-stamped. We don't verify the signature, this requires a trust store containing the trusted CAs.
 * Signature verification is left to the party that relies on the timestamp. */
static int verify_response_against_request(TS_RESP *resp, const void *request_der, size_t request_der_size) {
        assert(resp);
        assert(request_der);

        const unsigned char *p = request_der;
        _cleanup_(TS_REQ_freep) TS_REQ *req = sym_d2i_TS_REQ(NULL, &p, request_der_size);
        if (!req)
                return log_openssl_errors(LOG_ERR, "Failed to parse our own timestamp request.");

        _cleanup_(TS_VERIFY_CTX_freep) TS_VERIFY_CTX *ctx = sym_TS_REQ_to_TS_VERIFY_CTX(req, /* ctx= */ NULL);
        if (!ctx)
                return log_openssl_errors(LOG_ERR, "Failed to build verification context from our request.");

        int flags = TS_VFY_VERSION|TS_VFY_IMPRINT;
        if (sym_TS_REQ_get_nonce(req))
                flags |= TS_VFY_NONCE;

        if (sym_TS_VERIFY_CTX_set_flags(ctx, flags) < 0)
                return log_openssl_errors(LOG_ERR, "Failed to set verification flags.");

        if (sym_TS_RESP_verify_response(ctx, resp) != 1)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Timestamp response does not match the request we sent.");

        return 0;
}

/* Parse a DER-encoded TimeStampResp. On success (return 0) the caller must inspect resp->status.
 * Returns -EBADMSG if the response could not be parsed. */
int tsp_parse_response(
                const void *der,
                size_t der_size,
                const void *request_der,
                size_t request_der_size,
                TspResponse *resp) {

        int r;

        assert(der || der_size == 0);
        assert(request_der || request_der_size == 0);
        assert(resp);

        *resp = (TspResponse) { .status = -1 };

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        const unsigned char *p = der;
        _cleanup_(TS_RESP_freep) TS_RESP *tr = sym_d2i_TS_RESP(NULL, &p, (long) der_size);
        if (!tr)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse timestamp response DER.");

        TS_STATUS_INFO *si = sym_TS_RESP_get_status_info(tr);
        if (!si)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamp response carries no status.");

        const ASN1_INTEGER *st = sym_TS_STATUS_INFO_get0_status(si);
        if (!st)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamp response status info carries no status integer.");
        resp->status = sym_ASN1_INTEGER_get(st);

        r = parse_status_string(si, &resp->status_string);
        if (r < 0)
                return r;

        r = parse_failure_info(si, &resp->failure_info, &resp->n_failure_info);
        if (r < 0)
                return r;

        /* PKIStatus granted or grantedWithMods means a token is present. */
        if (!IN_SET(resp->status, TS_STATUS_GRANTED, TS_STATUS_GRANTED_WITH_MODS))
                return 0;

        /* RFC 3161 section 2.4.2 says that clients MUST generate an error if they do not understand a
         * value in the failInfo field. As we do report unknown bits in that field, instead just generate an
         * error if the field is present at all when a token was granted. */
        if (resp->n_failure_info > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Timestamp response is granted but carries failure info.");

        /* Check the token is a response to the request we actually sent, in particular that it echoes our
         * nonce back. */
        assert(request_der);
        r = verify_response_against_request(tr, request_der, request_der_size);
        if (r < 0)
                return r;

        PKCS7 *token = sym_TS_RESP_get_token(tr);
        if (!token)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Timestamp response is granted but carries no token.");

        _cleanup_(BIO_free_allp) BIO *bio = sym_BIO_new(sym_BIO_s_mem());
        if (!bio)
                return log_oom();

        if (sym_PEM_write_bio_PKCS7(bio, token) != 1)
                return log_openssl_errors(LOG_ERR, "Failed to PEM-encode timestamp token.");

        BUF_MEM *bm = NULL;
        sym_BIO_get_mem_ptr(bio, &bm);
        if (!bm || !bm->data)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Empty PEM output for timestamp token.");

        resp->token_pem = strndup(bm->data, bm->length);
        if (!resp->token_pem)
                return log_oom();

        return 0;
}
