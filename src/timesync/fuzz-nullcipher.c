/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "nts_crypto.h"
#include "timesyncd-forward.h"

/* Null cipher, to let the fuzzer also generate meaningful inputs for
 * the encrypted extension fields */

#define BLKSIZ 16

int NTS_encrypt(uint8_t *ctxt,
                int ctxt_len,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *nts,
                const uint8_t *key) {

        /* avoid 'unused' warnings */
        (void) info;
        (void) nts;
        (void) key;

        assert(ctxt_len >= ptxt_len + BLKSIZ);

        memset(ctxt, 0xEE, BLKSIZ);
        memmove(ctxt+BLKSIZ, ptxt, ptxt_len);
        return ptxt_len + BLKSIZ;
}

int NTS_decrypt(uint8_t *ptxt,
                int ptxt_len,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *nts,
                const uint8_t *key) {

        /* avoid 'unused' warnings */
        (void) info;
        (void) nts;
        (void) key;
        (void) ptxt_len;

        if (ctxt_len < BLKSIZ)
                return -1;

        assert(ptxt_len >= ctxt_len - BLKSIZ);

        memmove(ptxt, ctxt+16, ctxt_len - BLKSIZ);
        return ctxt_len - BLKSIZ;
}

const struct NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        static struct NTS_AEADParam param = {
                NTS_AEAD_AES_SIV_CMAC_256, 256/8, BLKSIZ, BLKSIZ, true, false, "AES-128-SIV"
        };
        return id? &param : NULL;
}
