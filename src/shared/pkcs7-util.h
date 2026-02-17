/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/uio.h>

typedef struct Signer {
        struct iovec issuer;
        struct iovec serial;
} Signer;

void signer_free_many(Signer *signers, size_t n);

int pkcs7_extract_signers(
                const struct iovec *sig,
                Signer **ret_signers,
                size_t *ret_n_signers);
