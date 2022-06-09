/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ask-password-api.h"
#include "libsss-util.h"
#include "cryptsetup-passphrase.h"
#include "libsss-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "json.h"
#include "parse-util.h"
#include "random-util.h"
#include "strv.h"

int find_passphrase_auto_data(
                Factor *factor,
                Factor *factor_list,
                uint16_t factor_number,
                struct crypt_device *cd,
                unsigned char **ret_encrypted_share,
                int *ret_keyslot) {

        size_t encrypted_share_size = 0;
        _cleanup_free_ char *rp = NULL;
        int r, keyslot = -1;

        assert(cd);
        assert(ret_keyslot);

        /* Loads passphrase metadata from LUKS2 JSON token headers. */
        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
                JsonVariant *w;
                int ks;

                /* If the asked factor is already assigned to a token, it means this token was not a valid one,
                 * thus we try to fetch the next one to check the integrity. */
                if (factor->token > -1) {
                        token = factor->token + 1;
                        factor->token = -1;
                }

                // If the token is already assigned, skip and try another
                if (is_factor_already_assigned(factor_list, factor_number, token))
                    continue ;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-passphrase", &v);
                if (IN_SET(r, -EMEDIUMTYPE))
                        continue ;
                if (IN_SET(r, -ENOENT, -EINVAL))
                        return log_error_errno(r, "No JSON token data: %m");
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                assert(keyslot < 0);
                ks = cryptsetup_get_keyslot_from_token(v);
                if (ks < 0)
                        return log_error_errno(ks, "Failed to extract keyslot index from passphrase JSON data: %m");
                if (*ret_keyslot >= 0 && *ret_keyslot != ks) {
                        continue ;
                }
                *ret_keyslot = ks;
                if (factor_number > 1) {
                        r = fetch_sss_json_data(factor, v, ret_encrypted_share);
                        if (r == -EAGAIN)
                                continue;
                        if (r < 0)
                                return r;
                }
                factor->token = token;
                break ;
        }

        log_debug("Automatically discovered security passphrase token unlocks volume.");
        return 0;
}
