/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "memory-util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/* algorithm type is not made into a full enum since it eases ptr-conversions */
typedef uint16_t NTS_AEADAlgorithmType;
enum {
        NTS_AEAD_AES_SIV_CMAC_256 = 15,
        NTS_AEAD_AES_SIV_CMAC_384 = 16,
        NTS_AEAD_AES_SIV_CMAC_512 = 17,
        NTS_AEAD_AES_128_GCM_SIV  = 30,
        NTS_AEAD_AES_256_GCM_SIV  = 31,
};

typedef struct NTS_AEADParam {
        uint8_t aead_id, key_size, block_size, nonce_size;
        bool tag_first, nonce_is_iv;
        const char *cipher_name;
} NTS_AEADParam;

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

        NTS_SUCCESS = -1,
} NTS_ErrorType;

typedef struct NTS_Cookie {
        uint8_t *data;
        size_t length;
} NTS_Cookie;

typedef struct NTS_Agreement {
        enum NTS_ErrorType error;

        NTS_AEADAlgorithmType aead_id;

        const char *ntp_server;
        uint16_t ntp_port;

        struct NTS_Cookie cookie[8];
} NTS_Agreement;

/* Encode a NTS KE request in the buffer of the provided size. If the third argument is not NULL,
 * it must point to a NULL-terminated array of AEAD_algorithm-types that indicate the preferred AEAD
 * algorithms (otherwise a sane default it used).
 *
 * RETURNS
 *      non-zero number of bytes encoded upon success
 *      negative value upon failure (not enough room in buffer)
 */
int NTS_encode_request(uint8_t *buffer, size_t buf_size, const NTS_AEADAlgorithmType[]);

/* Decode a NTS KE reponse in the buffer of the provided size, and write the result to the NTS_reponse
 * struct.
 *
 * RETURNS
 *      0 upon success
 *      negative upon failure (writes the error code to NTS_Agreement->error)
 */
int NTS_decode_response(uint8_t *buffer, size_t buf_size, struct NTS_Agreement *);

/* Convert a NTS_ErrorType to a string */
const char *NTS_error_string(enum NTS_ErrorType error);

/* The following three functions provide runtime information about the chosen AEAD algorithm:
 * - key size requirement in bytes
 * - OpenSSL name of the AEAD algorithm
 * - Fetched EVP_CIPHER for the AEAD algorithm (when SIV is provided by OpenSSL only)
 */

const struct NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType);

/* An opaque type that represents the underlying TLS session */
typedef struct NTS_TLS NTS_TLS;

/* Perform key extraction on the TLS session using the specified algorithm_type. C2S and S2C must point to
 * buffers that provide key_capacity amount of bytes.
 *
 * FIXME: https://github.com/pendulum-project/nts-timesyncd/issues/6
 *
 * RETURNS
 *      0 upon success
 *      a negative value upon failure:
 *              -1 OpenSSL error
 *              -2 not enough space in buffer
 *              -3 unkown AEAD
 */
int NTS_TLS_extract_keys(NTS_TLS *session, NTS_AEADAlgorithmType, uint8_t *c2s, uint8_t *s2c, int key_capacity);

/* Setup a ready-to-use TLS session for hostname, on the connected socket, ready to begin a TLS handshake.
 *
 * RETURNS
 *      A pointer to a ready-to-use TLS session, NULL upon failure (and then the error is stored in NTS_TLS_error)
 */
NTS_TLS* NTS_TLS_setup(const char *hostname, int socket);

/* Perform a TLS handshake
 *
 * FIXME: https://github.com/pendulum-project/nts-timesyncd/issues/6
 *
 * RETURNS
 *      0 upon success
 *      1 if it needs to be retried (e.g. if the socket is non-blocking)
 *     -1 upon permanent failure
 *
 */
int NTS_TLS_handshake(NTS_TLS *session);

/* Shutdowns a TLS session and frees all resources, closes the associated socket
 *
 * RETURNS
 *      Nothing
 */
void NTS_TLS_close(NTS_TLS *session);

/* Reading and writing data
 *
 * RETURNS
 *      > 0 the number of bytes processed
 *      0   an error occurred, please retry
 *      < 0 an error occurred, do not retry
 */
ssize_t NTS_TLS_write(NTS_TLS *session, const void *buffer, size_t size);
ssize_t NTS_TLS_read(NTS_TLS *session, void *buffer, size_t size);

/* Convenience function for creating a TCP connection
 *
 * RETURNS
 *      >= 0 an opened socket
 *      < 0  error
 */
int NTS_attach_socket(const char *host, int port, int type);
