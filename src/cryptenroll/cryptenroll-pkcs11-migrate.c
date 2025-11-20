/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-pkcs11-migrate.h"
#include "cryptsetup-util.h"
#include "sd-json.h"
#include "json-util.h"
#include "log.h"
#include "memory-util.h"
#include "strv.h"

int migrate_pkcs11_to_oaep(struct crypt_device *cd) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *jwe = NULL, *jwe_array = NULL;
        _cleanup_strv_free_ char **array = NULL;
        int r, migrated = 0, skipped = 0;

        assert(cd);

        for (int token = 0; token < crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                sd_json_variant *w, *alg_field;
                const char *type, *algorithm = NULL;

                r = cryptsetup_get_token_as_json(cd, token, NULL, &v);
                if (IN_SET(r, -ENOENT, -EINVAL))
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to read JSON token %i, skipping: %m", token);
                        continue;
                }

                w = sd_json_variant_by_key(v, "type");
                if (!w || !sd_json_variant_is_string(w)) {
                        log_warning("Token %i lacks 'type' field, skipping.", token);
                        continue;
                }

                type = sd_json_variant_string(w);
                if (!streq(type, "systemd-pkcs11")) {
                        log_debug("Token %i is not a PKCS#11 token (type=%s), skipping.", token, type);
                        continue;
                }

                /* Check if already migrated */
                alg_field = sd_json_variant_by_key(v, "pkcs11-key-algorithm");
                if (alg_field) {
                        algorithm = sd_json_variant_string(alg_field);
                        if (algorithm && streq(algorithm, "rsa-oaep-sha256")) {
                                log_info("Token %i already uses RSA-OAEP, skipping.", token);
                                skipped++;
                                continue;
                        }
                }

                /* Update algorithm field */
                r = sd_json_variant_set_field_string(&v, "pkcs11-key-algorithm", "rsa-oaep-sha256");
                if (r < 0) {
                        log_warning_errno(r, "Failed to update token %i algorithm field: %m", token);
                        continue;
                }

                /* Update token */
                r = cryptsetup_add_token_json(cd, v);
                if (r < 0) {
                        log_warning_errno(r, "Failed to update token %i: %m", token);
                        continue;
                }

                log_info("Migrated token %i from %s to RSA-OAEP.",
                         token,
                         algorithm ? algorithm : "rsa-pkcs1-v1.5");
                migrated++;
        }

        if (migrated == 0 && skipped == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                      "No PKCS#11 tokens found to migrate.");

        if (migrated > 0)
                log_info("Successfully migrated %i PKCS#11 token(s) to RSA-OAEP.", migrated);

        if (skipped > 0)
                log_info("Skipped %i already migrated token(s).", skipped);

        return 0;
}