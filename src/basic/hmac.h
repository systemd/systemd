/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "md5.h"
#include "sha256.h"

/* Unoptimized implementation based on FIPS 198. 'res' has to be allocated by
 * the caller. Prefer external OpenSSL functions, and use this only when
 * linking to OpenSSL is not desirable (eg: libsystemd.so). */
void hmac_sha256(const void *key, size_t key_size, const void *input, size_t input_size, uint8_t res[static SHA256_DIGEST_SIZE]);

/* HMAC-MD5 (RFC 2104). Only for protocols that mandate it, see md5.h. */
void hmac_md5(const void *key, size_t key_size, const void *input, size_t input_size, uint8_t res[static MD5_DIGEST_SIZE]);
