/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_OPENSSL

#include "openssl-util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(HMAC_CTX*, HMAC_CTX_free);

int hmac(
        const EVP_MD *alg,
        const uint8_t *key,
        int key_len,
        const uint8_t *msg,
        int msg_len,
        uint8_t *md,
        unsigned int *md_len) {

        _cleanup_(HMAC_CTX_freep) HMAC_CTX *ctx = NULL;
        unsigned int len;
        int r;

        assert(alg);
        assert(key);
        assert(md);

        ctx = HMAC_CTX_new();
        if (!ctx)
                /* OpenSSL isn't giving us much help here, but this function
                 * only returns NULL on failed allocations. */
                return -ENOMEM;

        r = HMAC_Init_ex(ctx, key, key_len, alg, NULL);
        if (r == 0)
                return -EIO;

        r = HMAC_Update(ctx, msg, msg_len);
        if (r == 0)
                return -EIO;

        r = HMAC_Final(ctx, md, &len);
        if (r == 0)
                return -EIO;

        if (md_len)
                *md_len = len;

        return 0;
}
#endif
