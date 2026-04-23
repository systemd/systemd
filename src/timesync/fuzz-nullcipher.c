/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <string.h>

#include "nts_crypto.h"
#include "timesyncd-forward.h"

/* Null cipher, to let the fuzzer also generate meaningful inputs for
 * the encrypted extension fields */

#define BLKSIZ 16

int NTS_encrypt(uint8_t *ctxt,
                size_t ctxt_len,
                const uint8_t *ptxt,
                size_t ptxt_len,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        /* avoid 'unused' warnings */
        (void) info;
        (void) aead;
        (void) key;

        assert(ctxt_len >= ptxt_len + BLKSIZ);

        memset(ctxt, 0xEE, BLKSIZ);
        memmove(ctxt+BLKSIZ, ptxt, ptxt_len);
        return ptxt_len + BLKSIZ;
}

int NTS_decrypt(uint8_t *ptxt,
                size_t ptxt_len,
                const uint8_t *ctxt,
                size_t ctxt_len,
                const AssociatedData *info,
                const NTS_AEADParam *aead,
                const uint8_t *key) {

        /* avoid 'unused' warnings */
        (void) info;
        (void) aead;
        (void) key;
        (void) ptxt_len;

        if (ctxt_len < BLKSIZ)
                return -1;

        assert(ptxt_len >= ctxt_len - BLKSIZ);

        memmove(ptxt, ctxt+16, ctxt_len - BLKSIZ);
        return ctxt_len - BLKSIZ;
}

const NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        static NTS_AEADParam param = {
                NTS_AEAD_AES_SIV_CMAC_256, 256/8, BLKSIZ, BLKSIZ, true, false, "AES-128-SIV"
        };
        return id? &param : NULL;
}
