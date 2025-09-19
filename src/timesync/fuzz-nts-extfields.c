/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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

        struct NTS_Query nts = {
                .cipher = *NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256),
                .c2s_key = (void*)"01234567890abcdef",
                .s2c_key = (void*)"01234567890abcdef",
        };

        /* fuzz the NTS extension field parser */
        struct NTS_Receipt rcpt = {};
        if (NTS_parse_extension_fields(buffer, len, &nts, &rcpt)) {
                FOREACH_ELEMENT(cookie, rcpt.new_cookie)
                        eat(cookie->data, cookie->length);

                eat(*rcpt.identifier, 32);
        }

        return 0;
}

/* Null cipher, to let the fuzzer also generate meaningful inputs for
 * the encrypted extension fields */

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
