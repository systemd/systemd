/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* MD5 as specified in RFC 1321. MD5 is broken as a cryptographic hash function. It is only provided for
 * protocols that mandate it, e.g. HMAC-MD5 in the DHCPv6 Reconfigure Key Authentication Protocol (RFC 9915)
 * and the DHCPv4 Forcerenew Nonce Authentication (RFC 6704). Do not use it for anything else. */

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE 64

struct md5_ctx {
        uint32_t state[4];
        uint64_t size;  /* total number of bytes processed */
        uint8_t buffer[MD5_BLOCK_SIZE];
};

void md5_init_ctx(struct md5_ctx *ctx);
void md5_process_bytes(const void *buffer, size_t len, struct md5_ctx *ctx);
uint8_t* md5_finish_ctx(struct md5_ctx *ctx, uint8_t result[static MD5_DIGEST_SIZE]);

uint8_t* md5_direct(const void *buffer, size_t sz, uint8_t result[static MD5_DIGEST_SIZE]);
