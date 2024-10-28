/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptenroll-recovery.h"
#include "glyph-util.h"
#include "json.h"
#include "memory-util.h"
#include "qrcode-util.h"
#include "recovery-key.h"
#include "terminal-util.h"

int enroll_recovery(
                struct crypt_device *cd,
                const void *volume_key,
                size_t volume_key_size) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_(erase_and_freep) char *password = NULL;
        _cleanup_free_ char *keyslot_as_string = NULL;
        int keyslot, r, q;
        const char *node;

        assert_se(cd);
        assert_se(volume_key);
        assert_se(volume_key_size > 0);

        assert_se(node = crypt_get_device_name(cd));

        r = make_recovery_key(&password);
        if (r < 0)
                return log_error_errno(r, "Failed to generate recovery key: %m");

        r = cryptsetup_set_minimal_pbkdf(cd);
        if (r < 0)
                return log_error_errno(r, "Failed to set minimal PBKDF: %m");

        keyslot = crypt_keyslot_add_by_volume_key(
                        cd,
                        CRYPT_ANY_SLOT,
                        volume_key,
                        volume_key_size,
                        password,
                        strlen(password));
        if (keyslot < 0)
                return log_error_errno(keyslot, "Failed to add new recovery key to %s: %m", node);

        fflush(stdout);
        fprintf(stderr,
                "A secret recovery key has been generated for this volume:\n\n"
                "    %s%s%s",
                emoji_enabled() ? special_glyph(SPECIAL_GLYPH_LOCK_AND_KEY) : "",
                emoji_enabled() ? " " : "",
                ansi_highlight());
        fflush(stderr);

        fputs(password, stdout);
        fflush(stdout);

        fputs(ansi_normal(), stderr);
        fflush(stderr);

        fputc('\n', stdout);
        fflush(stdout);

        fputs("\nPlease save this secret recovery key at a secure location. It may be used to\n"
              "regain access to the volume if the other configured access credentials have\n"
              "been lost or forgotten. The recovery key may be entered in place of a password\n"
              "whenever authentication is requested.\n", stderr);
        fflush(stderr);

        (void) print_qrcode(stderr, "Optionally scan the recovery key for safekeeping", password);

        if (asprintf(&keyslot_as_string, "%i", keyslot) < 0) {
                r = log_oom();
                goto rollback;
        }

        r = json_build(&v,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("type", JSON_BUILD_CONST_STRING("systemd-recovery")),
                                       JSON_BUILD_PAIR("keyslots", JSON_BUILD_ARRAY(JSON_BUILD_STRING(keyslot_as_string)))));
        if (r < 0) {
                log_error_errno(r, "Failed to prepare recovery key JSON token object: %m");
                goto rollback;
        }

        r = cryptsetup_add_token_json(cd, v);
        if (r < 0) {
                log_error_errno(r, "Failed to add recovery JSON token to LUKS2 header: %m");
                goto rollback;
        }

        log_info("New recovery key enrolled as key slot %i.", keyslot);
        return keyslot;

rollback:
        q = crypt_keyslot_destroy(cd, keyslot);
        if (q < 0)
                log_debug_errno(q, "Unable to remove key slot we just added again, can't rollback, sorry: %m");

        return r;
}
