/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "nts_crypto.h"
#include "timesyncd-forward.h"

/* Null cipher, to let the fuzzer also generate meaningful inputs for
 * the encrypted extension fields */

#define BLKSIZ 16

ssize_t NTS_encrypt(
                const struct iovec *ctxt,
                const struct iovec *ptxt,
                _unused_ const AssociatedData *info,
                _unused_ const NTS_AEADParam *aead,
                _unused_ const uint8_t *key) {

        assert(ctxt);
        assert(ptxt);

        uint8_t *ctxt_buf = ctxt->iov_base;
        size_t ctxt_len = ctxt->iov_len;
        const uint8_t *ptxt_buf = ptxt->iov_base;
        size_t ptxt_len = ptxt->iov_len;

        /* Bounds assertions enforced in NTS_encrypt */
        assert(ctxt_len <= (size_t) INT_MAX);
        assert(ptxt_len <= (size_t) INT_MAX);

        assert(ctxt_len >= ptxt_len + BLKSIZ);

        memset(ctxt_buf, 0xEE, BLKSIZ);
        memmove(ctxt_buf + BLKSIZ, ptxt_buf, ptxt_len);
        return ptxt_len + BLKSIZ;
}

ssize_t NTS_decrypt(
                const struct iovec *ptxt,
                const struct iovec *ctxt,
                _unused_ const AssociatedData *info,
                _unused_ const NTS_AEADParam *aead,
                _unused_ const uint8_t *key) {

        assert(ptxt);
        assert(ctxt);

        uint8_t *ptxt_buf = ptxt->iov_base;
        size_t ptxt_len = ptxt->iov_len;
        const uint8_t *ctxt_buf = ctxt->iov_base;
        size_t ctxt_len = ctxt->iov_len;

        /* Bounds assertions enforced in NTS_decrypt */
        assert(ptxt_len <= (size_t) INT_MAX);
        assert(ctxt_len <= (size_t) INT_MAX);

        if (ctxt_len < BLKSIZ)
                return -EINVAL;

        assert(ptxt_len >= ctxt_len - BLKSIZ);

        memmove(ptxt_buf, ctxt_buf + BLKSIZ, ctxt_len - BLKSIZ);
        return ctxt_len - BLKSIZ;
}

const NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        static const NTS_AEADParam param = {
                .aead_id     = NTS_AEAD_AES_SIV_CMAC_256,
                .key_size    = 256/8,
                .block_size  = BLKSIZ,
                .nonce_size  = BLKSIZ,
                .tag_first   = true,
                .nonce_is_iv = false,
                .cipher_name = "AES-128-SIV",
        };
        return id ? &param : NULL;
}
