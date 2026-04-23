/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright © 2026 Trifecta Tech Foundation */

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "fuzz.h"
#include "nts.h"
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
        if (len < 48)
                return 0;

        memcpy(buffer, data, len);

        NTS_Query nts = {
                .cipher = *NTS_get_param(NTS_AEAD_AES_SIV_CMAC_256),
                .c2s_key = (void*)"01234567890abcdef",
                .s2c_key = (void*)"01234567890abcdef",
        };

        /* fuzz the NTS extension field parser */
        NTS_Receipt rcpt = {};
        if (NTS_parse_extension_fields(buffer, len, &nts, &rcpt)) {
                FOREACH_ELEMENT(cookie, rcpt.new_cookie)
                        eat(cookie->data, cookie->length);

                eat(*rcpt.identifier, 32);
        }

        return 0;
}
