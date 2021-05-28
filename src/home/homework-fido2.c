/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fido.h>

#include "hexdecoct.h"
#include "homework-fido2.h"
#include "libfido2-util.h"
#include "memory-util.h"
#include "strv.h"

int fido2_use_token(
                UserRecord *h,
                UserRecord *secret,
                const Fido2HmacSalt *salt,
                char **ret) {

        _cleanup_(erase_and_freep) void *hmac = NULL;
        size_t hmac_size;
        Fido2EnrollFlags flags = 0;
        int r;

        assert(h);
        assert(secret);
        assert(salt);
        assert(ret);

        /* If we know the up/uv/clientPin settings used during enrollment, let's pass this on for
         * authentication, or generate errors immediately if interactivity of the specified kind is not
         * allowed. */

        if (salt->up > 0) {
                if (h->fido2_user_presence_permitted <= 0)
                        return -EMEDIUMTYPE;

                flags |= FIDO2ENROLL_UP;
        } else if (salt->up < 0) /* unset? */
                flags |= FIDO2ENROLL_UP_IF_NEEDED; /* compat with pre-248 */

        if (salt->uv > 0) {
                if (h->fido2_user_verification_permitted <= 0)
                        return -ENOCSI;

                flags |= FIDO2ENROLL_UV;
        } else if (salt->uv < 0)
                flags |= FIDO2ENROLL_UV_OMIT; /* compat with pre-248 */

        if (salt->client_pin > 0) {

                if (strv_isempty(secret->token_pin))
                        return -ENOANO;

                flags |= FIDO2ENROLL_PIN;
        } else if (salt->client_pin < 0)
                flags |= FIDO2ENROLL_PIN_IF_NEEDED; /* compat with pre-248 */

        r = fido2_use_hmac_hash(
                        NULL,
                        "io.systemd.home",
                        salt->salt, salt->salt_size,
                        salt->credential.id, salt->credential.size,
                        secret->token_pin,
                        flags,
                        &hmac,
                        &hmac_size);
        if (r < 0)
                return r;

        r = base64mem(hmac, hmac_size, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode HMAC secret: %m");

        return 0;
}
