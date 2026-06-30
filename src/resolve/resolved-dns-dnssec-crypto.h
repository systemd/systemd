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

#endif
