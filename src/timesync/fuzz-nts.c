/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include "fuzz.h"

#include "nts.h"
#include "nts_crypto.h"
#include "nts_extfields.h"

static void eat(const uint8_t *buf, size_t size) {
        if (!buf)
                return;

        while (size--)
                DO_NOT_OPTIMIZE(buf[size]);
}

/* this program does no sanity checking as it is meant for fuzzing only */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        uint8_t buffer[1280];
        int len = MIN(size, sizeof(buffer));

        memcpy(buffer, data, len);
        if (len < 48)
                return 0;

        /* fuzz the nts ke routines */
        struct NTS_Agreement rec;
        if (NTS_decode_response(buffer, len, &rec) == 0) {
                FOREACH_ELEMENT(cookie, rec.cookie)
                        eat(cookie->data, cookie->length);
        }

        return 0;
}

/* null cipher */

#define BLKSIZ 16

int NTS_encrypt(uint8_t *ctxt,
                const uint8_t *ptxt,
                int ptxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *nts,
                const uint8_t *key) {
        (void) info;
        (void) nts;
        (void) key;
        memset(ctxt, 0xEE, BLKSIZ);
        memmove(ctxt+BLKSIZ, ptxt, ptxt_len);
        return ptxt_len + BLKSIZ;
}

int NTS_decrypt(uint8_t *ptxt,
                const uint8_t *ctxt,
                int ctxt_len,
                const AssociatedData *info,
                const struct NTS_AEADParam *nts,
                const uint8_t *key) {
        (void) info;
        (void) nts;
        (void) key;
        if (ctxt_len < BLKSIZ)
                return -1;

        memmove(ptxt, ctxt+16, ctxt_len - BLKSIZ);
        return ctxt_len - BLKSIZ;
}

const struct NTS_AEADParam* NTS_get_param(NTS_AEADAlgorithmType id) {
        static struct NTS_AEADParam param = {
                NTS_AEAD_AES_SIV_CMAC_256, 256/8, 16, 16, true, false, "AES-128-SIV"
        };
        return id? &param : NULL;
}
