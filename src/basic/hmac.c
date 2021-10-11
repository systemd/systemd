/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "hmac.h"
#include "sha256.h"

#define HMAC_BLOCK_SIZE 64
#define INNER_PADDING_BYTE 0x36
#define OUTER_PADDING_BYTE 0x5c

/* start/add/end implement the HMAC algorithm as described by FIPS 198. */

void hmac_sha256_start(Hmac *hmac,
                       const void *key,
                       size_t key_size) {

        uint8_t inner_padding[HMAC_BLOCK_SIZE] = { };

        assert(hmac);
        assert(key);
        assert(key_size > 0);

        /* The key needs to be block size length or less, hash it if it's longer. */
        if (key_size > HMAC_BLOCK_SIZE) {
                struct sha256_ctx hash;

                sha256_init_ctx(&hash);
                sha256_process_bytes(key, key_size, &hash);
                sha256_finish_ctx(&hash, hmac->key);
                hmac->key_size = SHA256_DIGEST_SIZE;
        } else {
                hmac->key_size = key_size;
                memcpy(hmac->key, key, key_size);
        }

        /* First, copy the key into the padding array. If it's shorter than
         * the block size, the array is already initialized to 0. */
        memcpy(inner_padding, hmac->key, hmac->key_size);

        /* Then, XOR the provided key and any padding leftovers with the fixed
         * padding bytes as defined in FIPS 198. */
        for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++)
                inner_padding[i] ^= INNER_PADDING_BYTE;

        /* First pass: hash the inner padding array. */
        sha256_init_ctx(&hmac->hash);
        sha256_process_bytes(inner_padding, HMAC_BLOCK_SIZE, &hmac->hash);
}

void hmac_sha256_add(Hmac *hmac,
                     const void *input,
                     size_t input_size) {

        assert(hmac);

        if (!input || input_size == 0)
                return;

        /* Keep adding the input buffers to the first pass hash. */
        sha256_process_bytes(input, input_size, &hmac->hash);
}

static void hmac_sha256_end_internal(Hmac *hmac,
                                     uint8_t *res) {

        uint8_t outer_padding[HMAC_BLOCK_SIZE] = { };

        assert(hmac);
        assert(hmac->key_size > 0);

        /* First, copy the key into the padding arrays. If it's shorter than
         * the block size, the array is already initialized to 0. */
        memcpy(outer_padding, hmac->key, hmac->key_size);

        /* Then, XOR the provided key and any padding leftovers with the fixed
         * padding bytes as defined in FIPS 198. */
        for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++)
                outer_padding[i] ^= OUTER_PADDING_BYTE;

        /* Second pass: hash the outer padding array and the result of the first pass. */
        sha256_finish_ctx(&hmac->hash, hmac->res);
        sha256_init_ctx(&hmac->hash);
        sha256_process_bytes(outer_padding, HMAC_BLOCK_SIZE, &hmac->hash);
        sha256_process_bytes(hmac->res, SHA256_DIGEST_SIZE, &hmac->hash);
        sha256_finish_ctx(&hmac->hash, res ?: hmac->res);
}

void hmac_sha256_end(Hmac *hmac) {
        hmac_sha256_end_internal(hmac, NULL);
}

void hmac_sha256(const void *key,
                 size_t key_size,
                 const void *input,
                 size_t input_size,
                 uint8_t res[static SHA256_DIGEST_SIZE]) {

        Hmac hmac = { };

        assert(key);
        assert(key_size > 0);
        assert(res);

        hmac_sha256_start(&hmac, key, key_size);
        hmac_sha256_add(&hmac, input, input_size);
        hmac_sha256_end_internal(&hmac, res);
}
