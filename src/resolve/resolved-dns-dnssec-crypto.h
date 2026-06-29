/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "crypto-util.h"
#include "shared-forward.h"

#if HAVE_OPENSSL

int dnssec_rsa_verify_raw(
                const EVP_MD *hash_algorithm,
                const void *signature, size_t signature_size,
                const void *data, size_t data_size,
                const void *exponent, size_t exponent_size,
                const void *modulus, size_t modulus_size);

#endif
