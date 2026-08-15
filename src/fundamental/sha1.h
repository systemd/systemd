/* SPDX-License-Identifier: LicenseRef-alg-sha1-public-domain */

/*
 * This is an implementation of the National Institute of Standards
 * and Technology US Secure Hash Algorithm 1 (SHA1).
 *
 * Public api for steve reid's public domain SHA-1 implementation.
 * This file is in the public domain.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_SIZE 20

/* Structure to save state of computation between the single steps.  */
struct sha1_ctx {
        uint32_t state[5];
        uint32_t count[2];
        uint8_t buffer[64];
};

/* Initialize structure containing state of computation.
   (RFC 3174, 6.1)  */
void sha1_init_ctx(struct sha1_ctx *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function) update the context for the next LEN bytes
   starting at BUFFER.  LEN does not need to be a multiple of 64.  */
void sha1_process_bytes(const void *buffer, size_t size, struct sha1_ctx *ctx);

/* Process the remaining bytes in the buffer and write the finalized
   hash to RESBUF, which should point to 20 bytes of storage.  All
   data written to CTX is erased before returning from the function.  */
void *sha1_finish_ctx(struct sha1_ctx *ctx, uint8_t result[static SHA1_DIGEST_SIZE]);
