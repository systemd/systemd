/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "nts_definitions.h"

typedef uint16_t NTS_RecordType;
typedef uint16_t NTS_AEADAlgorithmType;
typedef uint16_t NTS_ProtocolType;

typedef struct NTS_AEADParam {
        NTS_AEADAlgorithmType aead_id;
        uint8_t key_size, block_size, nonce_size;
        bool tag_first, nonce_is_iv;
        const char *cipher_name;
} NTS_AEADParam;

typedef uint8_t NTS_Identifier[32];

typedef enum NTS_ErrorType {
        NTS_SERVER_UNKNOWN_CRIT_RECORD = 0,
        NTS_SERVER_BAD_REQUEST = 1,
        NTS_SERVER_INTERNAL_ERROR = 2,

        NTS_UNEXPECTED_WARNING = 0x10000,
        NTS_BAD_RESPONSE = 0x10001,
        NTS_INTERNAL_CLIENT_ERROR = 0x10002,
        NTS_NO_PROTOCOL = 0x10003,
        NTS_NO_AEAD = 0x10004,
        NTS_INSUFFICIENT_DATA = 0x10005,
        NTS_UNKNOWN_CRIT_RECORD = 0x10006,

        NTS_SUCCESS = 0x20000,

        _NTS_ERROR_MAX,
        _NTS_ERROR_INVALID = -EINVAL,
} NTS_ErrorType;

typedef struct iovec NTS_Cookie;

typedef struct NTS_Agreement {
        NTS_ErrorType error;

        NTS_AEADAlgorithmType aead_id;

        const char *ntp_server;
        uint16_t ntp_port;

        NTS_Cookie cookie[8];
} NTS_Agreement;

/* Encode a NTS KE request in the buffer of the provided size. If the third argument is not NULL,
 * it must point to a NULL-terminated array of AEAD_algorithm-types that indicate the preferred AEAD
 * algorithms (otherwise a sane default it used).
 *
 * RETURNS
 *      non-zero number of bytes encoded upon success
 *      negative value upon failure (not enough room in buffer)
 */
int NTS_encode_request(uint8_t *buffer, size_t buf_size, const NTS_AEADAlgorithmType *preferred_crypto);

/* Decode a NTS KE reponse in the buffer of the provided size, and write the result to the NTS_Agreement
 * struct. This function does not allocate data: pointers in the struct for a potential negotiated server
 * name and NTS cookies point into buffer, and must be copied if buffer is deallocated or overwritten.
 *
 * Upon success, the input buffer may have been modified by the decoding process, so any writes to it
 * after that can cause undefined behaviour.
 *
 * If this function returns failure, the input buffer is NOT modified (and so can be extended when more
 * input has been received, and then NTS_decode_response can be retried)
 *
 * RETURNS
 *      0 upon success
 *      negative upon failure (writes the error code to NTS_Agreement->error)
 */
int NTS_decode_response(uint8_t *buffer, size_t buf_size, NTS_Agreement *response);

/* Convert a NTS_ErrorType to a string */
const char *NTS_error_string(NTS_ErrorType error);

/* The following three functions provide runtime information about the chosen AEAD algorithm:
 * - key size requirement in bytes
 * - OpenSSL name of the AEAD algorithm
 * - Fetched EVP_CIPHER for the AEAD algorithm (when SIV is provided by OpenSSL only)
 */

const NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id);

/* An opaque type that represents the underlying TLS session */
typedef struct NTS_TLS NTS_TLS;

/* Perform key extraction on the TLS session using the specified algorithm_type. C2S and S2C must point to
 * buffers that provide key_capacity amount of bytes.
 *
 * RETURNS
 *      0 upon success
 *      a negative value upon failure:
 *              -EBADE   OpenSSL error
 *              -ENOBUFS not enough space in buffer
 *              -EINVAL  unkown AEAD
 */
int NTS_TLS_extract_keys(NTS_TLS *session, NTS_AEADAlgorithmType aead, uint8_t *ret_c2s, uint8_t *ret_s2c, size_t key_capacity);

/* Setup a ready-to-use TLS session for hostname, on the connected socket, ready to begin a TLS handshake.
 *
 * RETURNS
 *      A pointer to a ready-to-use TLS session, NULL upon failure (and then the error is stored in NTS_TLS_error)
 */
NTS_TLS* NTS_TLS_setup(const char *hostname, int socket_fd);

/* Perform a TLS handshake
 *
 * RETURNS
 *      > 0 upon success
 *      0   if it needs to be retried (e.g. if the socket is non-blocking)
 *      < 0 upon permanent failure
 *
 */
int NTS_TLS_handshake(NTS_TLS *session);

/* Shutdowns a TLS session and frees all resources, closes the associated socket
 * Also sets the NTS_TLS* object itself to NULL.
 *
 * RETURNS
 *      Nothing
 */
NTS_TLS* NTS_TLS_free(NTS_TLS *session);

/* Reading and writing data
 *
 * RETURNS
 *      > 0 the number of bytes processed
 *      0   an error occurred, please retry
 *      < 0 an error occurred, do not retry
 */
ssize_t NTS_TLS_write(NTS_TLS *session, const void *buffer, size_t size);
ssize_t NTS_TLS_read(NTS_TLS *session, void *buffer, size_t size);
