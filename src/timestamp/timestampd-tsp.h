/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Helpers implementing the ASN.1/DER bits of the RFC 3161 Time-Stamp Protocol on top of OpenSSL. */

/* The parameters of a TimeStampResp, as returned by tsp_parse_response(). */
typedef struct TspResponse {
        int status;             /* RFC 3161 PKIStatus, or -1 if not determined */
        char *status_string;    /* human readable status text, or NULL */
        int *failure_info;      /* the PKIFailureInfo bits that are set, by bit number */
        size_t n_failure_info;
        char *token_pem;        /* PEM-encoded (PKCS7 label) time-stamp token, set if granted */
} TspResponse;

void tsp_response_done(TspResponse *r);

int tsp_hash_algorithm_from_string(const char *name, int *ret_nid, size_t *ret_digest_size);

int tsp_digest_fd(int md_nid, int fd, void **ret, size_t *ret_size);

int tsp_build_request(
                int md_nid,
                const void *digest,
                size_t digest_size,
                bool nonce,
                bool cert_req,
                void **ret,
                size_t *ret_size);

/* Parses a DER TimeStampResp. request_der must be the DER TimeStampReq this is a response to: a granted
 * response is checked against it, so that a token for somebody else's request, or for a different digest,
 * is not mistaken for ours. */
int tsp_parse_response(
                const void *der,
                size_t der_size,
                const void *request_der,
                size_t request_der_size,
                TspResponse *resp);
