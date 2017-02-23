#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <inttypes.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "macro.h"

typedef struct khash khash;

/* For plain hash functions. Hash functions commonly supported on today's kernels are: crc32c, crct10dif, crc32,
 * sha224, sha256, sha512, sha384, sha1, md5, md4, sha3-224, sha3-256, sha3-384, sha3-512, and more. */
int khash_new(khash **ret, const char *algorithm);

/* For keyed hash functions. Hash functions commonly supported on today's kernels are: hmac(sha256), cmac(aes),
 * cmac(des3_ede), hmac(sha3-512), hmac(sha3-384), hmac(sha3-256), hmac(sha3-224), hmac(rmd160), hmac(rmd128),
 * hmac(sha224), hmac(sha512), hmac(sha384), hmac(sha1), hmac(md5), and more. */
int khash_new_with_key(khash **ret, const char *algorithm, const void *key, size_t key_size);

int khash_dup(khash *h, khash **ret);
khash* khash_unref(khash *h);

const char *khash_get_algorithm(khash *h);
size_t khash_get_size(khash *h);

int khash_reset(khash *h);

int khash_put(khash *h, const void *buffer, size_t size);
int khash_put_iovec(khash *h, const struct iovec *iovec, size_t n);

int khash_digest_data(khash *h, const void **ret);
int khash_digest_string(khash *h, char **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(khash*, khash_unref);
