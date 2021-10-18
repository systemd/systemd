/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "sha256.h"

#define SHA256_DIGEST_SIZE 32

typedef struct Hmac {
        struct sha256_ctx hash;
        size_t key_size;
        uint8_t key[SHA256_DIGEST_SIZE];
        uint8_t res[SHA256_DIGEST_SIZE];
} Hmac;

/* Unoptimized implementation based on FIPS 198. 'res' has to be allocated by
 * the caller. Prefer external OpenSSL functions, and use this only when
 * linking to OpenSSL is not desireable (eg: libsystemd.so). */
void hmac_sha256(const void *key, size_t key_size, const void *input, size_t input_size, uint8_t res[static SHA256_DIGEST_SIZE]);

/* Same as above, but split in a start/add data/finish workflow to facilitate
 * adding multiple buffers to the hash more efficiently. */
void hmac_sha256_start(Hmac *hmac, const void *key,  size_t key_size);
void hmac_sha256_add(Hmac *hmac, const void *input, size_t input_size);
void hmac_sha256_end(Hmac *hmac);
