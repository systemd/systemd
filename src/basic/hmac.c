/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "hmac.h"
#include "sha256.h"

#define HMAC_BLOCK_SIZE 64
#define INNER_PADDING_BYTE 0x36
#define OUTER_PADDING_BYTE 0x5c

void hmac_sha256(const void *key,
                 size_t key_size,
                 const void *input,
                 size_t input_size,
                 uint8_t res[static SHA256_DIGEST_SIZE]) {

        uint8_t inner_padding[HMAC_BLOCK_SIZE] = { };
        uint8_t outer_padding[HMAC_BLOCK_SIZE] = { };
        uint8_t replacement_key[SHA256_DIGEST_SIZE];
        struct sha256_ctx hash;

        assert(key);
        assert(key_size > 0);
        assert(res);

        /* Implement algorithm as described by FIPS 198. */

        /* The key needs to be block size length or less, hash it if it's longer. */
        if (key_size > HMAC_BLOCK_SIZE) {
                sha256_direct(key, key_size, replacement_key);
                key = replacement_key;
                key_size = SHA256_DIGEST_SIZE;
        }

        /* First, copy the key into the padding arrays. If it's shorter than
         * the block size, the arrays are already initialized to 0. */
        memcpy(inner_padding, key, key_size);
        memcpy(outer_padding, key, key_size);

        /* Then, XOR the provided key and any padding leftovers with the fixed
         * padding bytes as defined in FIPS 198. */
        for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++) {
                inner_padding[i] ^= INNER_PADDING_BYTE;
                outer_padding[i] ^= OUTER_PADDING_BYTE;
        }

        /* First pass: hash the inner padding array and the input. */
        sha256_init_ctx(&hash);
        sha256_process_bytes(inner_padding, HMAC_BLOCK_SIZE, &hash);
        sha256_process_bytes(input, input_size, &hash);
        sha256_finish_ctx(&hash, res);

        /* Second pass: hash the outer padding array and the result of the first pass. */
        sha256_init_ctx(&hash);
        sha256_process_bytes(outer_padding, HMAC_BLOCK_SIZE, &hash);
        sha256_process_bytes(res, SHA256_DIGEST_SIZE, &hash);
        sha256_finish_ctx(&hash, res);
}
