/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "crypto-util.h"
#include "forward.h"

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
                const struct iovec *signature_r,
                const struct iovec *signature_s,
                const struct iovec *hash,
                const struct iovec *key);

#endif
