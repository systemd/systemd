/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hexdecoct.h"
#include "homework-pkcs11.h"
#include "pkcs11-util.h"
#include "strv.h"

int pkcs11_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        struct pkcs11_callback_data *data = ASSERT_PTR(userdata);
        _cleanup_free_ char *token_label = NULL;
        CK_TOKEN_INFO updated_token_info;
        size_t decrypted_key_size;
        CK_OBJECT_HANDLE object;
        CK_RV rv;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);

        /* Special return values:
         *
         * -ENOANO       → if we need a PIN but have none
         * -ERFKILL      → if a "protected authentication path" is needed but we have no OK to use it
         * -EOWNERDEAD   → if the PIN is locked
         * -ENOLCK       → if the supplied PIN is incorrect
         * -ETOOMANYREFS → ditto, but only a few tries left
         * -EUCLEAN      → ditto, but only a single try left
         */

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return log_oom();

        if (FLAGS_SET(token_info->flags, CKF_PROTECTED_AUTHENTICATION_PATH)) {

                if (data->secret->pkcs11_protected_authentication_path_permitted <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ERFKILL), "Security token requires authentication through protected authentication path.");

                rv = m->C_Login(session, CKU_USER, NULL, 0);
                if (rv != CKR_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));

                log_info("Successfully logged into security token '%s' via protected authentication path.", token_label);
                goto decrypt;
        }

        if (!FLAGS_SET(token_info->flags, CKF_LOGIN_REQUIRED)) {
                log_info("No login into security token '%s' required.", token_label);
                goto decrypt;
        }

        if (strv_isempty(data->secret->token_pin))
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO), "Security token requires PIN.");

        STRV_FOREACH(i, data->secret->token_pin) {
                rv = m->C_Login(session, CKU_USER, (CK_UTF8CHAR*) *i, strlen(*i));
                if (rv == CKR_OK) {
                        log_info("Successfully logged into security token '%s' with PIN.", token_label);
                        goto decrypt;
                }
                if (rv == CKR_PIN_LOCKED)
                        return log_error_errno(SYNTHETIC_ERRNO(EOWNERDEAD), "PIN of security token is blocked. Please unblock it first.");
                if (!IN_SET(rv, CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));
        }

        rv = m->C_GetTokenInfo(slot_id, &updated_token_info);
        if (rv != CKR_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to acquire updated security token information for slot %lu: %s", slot_id, p11_kit_strerror(rv));

        if (FLAGS_SET(updated_token_info.flags, CKF_USER_PIN_FINAL_TRY))
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "PIN of security token incorrect, only a single try left.");
        if (FLAGS_SET(updated_token_info.flags, CKF_USER_PIN_COUNT_LOW))
                return log_error_errno(SYNTHETIC_ERRNO(ETOOMANYREFS), "PIN of security token incorrect, only a few tries left.");

        return log_error_errno(SYNTHETIC_ERRNO(ENOLCK), "PIN of security token incorrect.");

decrypt:
        r = pkcs11_token_find_private_key(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_decrypt_data(m, session, object, data->encrypted_key->data, data->encrypted_key->size, &decrypted_key, &decrypted_key_size);
        if (r < 0)
                return r;

        if (base64mem(decrypted_key, decrypted_key_size, &data->decrypted_password) < 0)
                return log_oom();

        return 1;
}
