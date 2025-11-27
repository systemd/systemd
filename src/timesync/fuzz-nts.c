/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fuzz.h"

#include "nts.h"

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
