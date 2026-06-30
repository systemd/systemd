/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "crypto-util.h"
#include "shared-forward.h"

#if HAVE_OPENSSL

int dnssec_rsa_verify_raw(
                const EVP_MD *hash_algorithm,
                const struct iovec *signature,
                const struct iovec *hash,
                const struct iovec *exponent,
                const struct iovec *modulus);

int dnssec_ecdsa_verify_raw(
                const EVP_MD *hash_algorithm,
                int curve,
                const void *signature_r, size_t signature_r_size,
                const void *signature_s, size_t signature_s_size,
                const void *data, size_t data_size,
                const void *key, size_t key_size);

#endif
