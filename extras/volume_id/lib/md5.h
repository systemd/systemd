/* 
 * MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */

#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

struct md5_ctx {
	uint32_t hash[MD5_HASH_WORDS];
	uint32_t block[MD5_BLOCK_WORDS];
	uint64_t byte_count;
};

extern void md5_init(struct md5_ctx *mctx);
extern void md5_update(struct md5_ctx *mctx, const uint8_t *data, unsigned int len);
extern void md5_final(struct md5_ctx *mctx, uint8_t *out);
