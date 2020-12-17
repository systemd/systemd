/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fido.h>

#include "hexdecoct.h"
#include "homework-fido2.h"
#include "libfido2-util.h"
#include "memory-util.h"

int fido2_use_token(
                UserRecord *h,
                UserRecord *secret,
                const Fido2HmacSalt *salt,
                char **ret) {

        _cleanup_(erase_and_freep) void *hmac = NULL;
        size_t hmac_size;
        int r;

        assert(h);
        assert(secret);
        assert(salt);
        assert(ret);

        r = fido2_use_hmac_hash(
                        NULL,
                        "io.systemd.home",
                        salt->salt, salt->salt_size,
                        salt->credential.id, salt->credential.size,
                        secret->token_pin,
                        h->fido2_user_presence_permitted > 0,
                        &hmac,
                        &hmac_size);
        if (r < 0)
                return r;

        r = base64mem(hmac, hmac_size, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode HMAC secret: %m");

        return 0;
}
