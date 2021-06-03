/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include "cryptsetup-token-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "json.h"
#include "luks2-pkcs11.h"
#include "memory-util.h"
#include "pkcs11-util.h"
#include "time-util.h"

struct luks2_pkcs11_callback_data {
        struct crypt_device *cd;
        const char *pin;
        void *encrypted_key;
        size_t encrypted_key_size;
        void *decrypted_key;
        size_t decrypted_key_size;
};

static int pkcs11_token_login_by_pin(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slotid,
                const CK_TOKEN_INFO *token_info,
                const char *pin,
                struct crypt_device *cd) {

        _cleanup_free_ char *token_uri_string = NULL, *token_uri_escaped = NULL, *id = NULL, *token_label = NULL;
        _cleanup_(p11_kit_uri_freep) P11KitUri *token_uri = NULL;
        CK_TOKEN_INFO updated_token_info;
        int uri_result;
        CK_RV rv;

        assert(m);
        assert(token_info);

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return -ENOMEM;

        token_uri = uri_from_token_info(token_info);
        if (!token_uri)
                return -ENOMEM;

        uri_result = p11_kit_uri_format(token_uri, P11_KIT_URI_FOR_ANY, &token_uri_string);
        if (uri_result != P11_KIT_URI_OK) {
                crypt_log_error(cd, "Failed to format slot URI: %s", p11_kit_uri_message(uri_result));
                return EINVAL;
        }

        if (FLAGS_SET(token_info->flags, CKF_PROTECTED_AUTHENTICATION_PATH)) {
                rv = m->C_Login(session, CKU_USER, NULL, 0);
                if (rv != CKR_OK) {
                        crypt_log_error(cd, "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));
                        return -EIO;
                }

                crypt_log_verbose(cd, "Successfully logged into security token '%s' via protected authentication path.", token_label);
                return 0;
        }

        if (!FLAGS_SET(token_info->flags, CKF_LOGIN_REQUIRED)) {
                crypt_log_debug(cd, "No login into security token '%s' required.", token_label);
                return 0;
        }

        if (!pin) {
                crypt_log_verbose(cd, "PIN required for security token '%s'.", token_label);
                if (FLAGS_SET(token_info->flags, CKF_USER_PIN_FINAL_TRY))
                        crypt_log_error(cd, "Final try remaining on PIN for security token '%s'.", token_label);
                return -ENOANO; /* pin required from now on */
        }

        token_uri_escaped = cescape(token_uri_string);
        if (!token_uri_escaped)
                return -ENOMEM;

        id = strjoin("pkcs11:", token_uri_escaped);
        if (!id)
                return -ENOMEM;

        rv = m->C_Login(session, CKU_USER, (CK_UTF8CHAR*) pin, strlen(pin));
        if (rv == CKR_OK) {
                crypt_log_verbose(cd, "Successfully logged into security token '%s'.", token_label);
                return 0;
        }
        if (rv == CKR_PIN_LOCKED) {
                crypt_log_error(cd, "PIN has been locked, please reset PIN of security token '%s'.", token_label);
                return -EIO;
        }
        if (!IN_SET(rv, CKR_PIN_INCORRECT, CKR_PIN_LEN_RANGE)) {
                crypt_log_error(cd, "Failed to log into security token '%s': %s", token_label, p11_kit_strerror(rv));
                return -EIO;
        }

        crypt_log_verbose(cd, "PIN for token '%s' is incorrect, please try again.", token_label);

        /* Referesh the token info, so that we can prompt knowing the new flags if they changed. */
        rv = m->C_GetTokenInfo(slotid, &updated_token_info);
        if (rv != CKR_OK) {
                crypt_log_error(cd, "Failed to acquire updated security token information for slot %lu: %s",
                              slotid, p11_kit_strerror(rv));
                return -EIO;
        }

        if (FLAGS_SET(updated_token_info.flags, CKF_USER_PIN_FINAL_TRY))
                crypt_log_error(cd, "Final try remaining on PIN for security token '%s'.", token_label);

        return -ENOANO;
}

static int luks2_pkcs11_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        struct luks2_pkcs11_callback_data *data = userdata;
        CK_OBJECT_HANDLE object;
        int r;

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);
        assert(data);

        /* Called for every token matching our URI */

        r = pkcs11_token_login_by_pin(
                        m,
                        session,
                        slot_id,
                        token_info,
                        data->pin,
                        data->cd);
        if (r < 0)
                return r;

        r = pkcs11_token_find_private_key(m, session, uri, &object);
        if (r < 0)
                return r;

        r = pkcs11_token_decrypt_data(
                        m,
                        session,
                        object,
                        data->encrypted_key,
                        data->encrypted_key_size,
                        &data->decrypted_key,
                        &data->decrypted_key_size);
        if (r < 0)
                return r;

        return 0;
}

static void luks2_pkcs11_callback_data_release(struct luks2_pkcs11_callback_data *data) {
        erase_and_free(data->decrypted_key);
}

static int acquire_luks2_key_by_pin(
                struct crypt_device *cd,
                const char *pkcs11_uri,
                const char *pin,
                void *encrypted_key,
                size_t encrypted_key_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        int r;
        _cleanup_(luks2_pkcs11_callback_data_release) struct luks2_pkcs11_callback_data data = {
                .cd = cd,
                .pin = pin,
                .encrypted_key = encrypted_key,
                .encrypted_key_size = encrypted_key_size,
        };

        assert(pkcs11_uri);
        assert(encrypted_key);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        r = pkcs11_find_token(pkcs11_uri, luks2_pkcs11_callback, &data);
        if (r < 0)
                return r;

        *ret_decrypted_key = TAKE_PTR(data.decrypted_key);
        *ret_decrypted_key_size = data.decrypted_key_size;

        return 0;
}

/* called from within systemd utilities */
static int acquire_luks2_key_systemd(
                const char *pkcs11_uri,
                systemd_pkcs11_plugin_params *params,
                void *encrypted_key,
                size_t encrypted_key_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        int r;
        _cleanup_(pkcs11_crypt_device_callback_data_release) pkcs11_crypt_device_callback_data data = {
                .encrypted_key = encrypted_key,
                .encrypted_key_size = encrypted_key_size,
                .free_encrypted_key = false
        };

        assert(pkcs11_uri);
        assert(encrypted_key);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);
        assert(params);

        data.friendly_name = params->friendly_name;
        data.headless = params->headless;
        data.until = params->until;

        /* The functions called here log about all errors, except for EAGAIN which means "token not found right now" */
        r = pkcs11_find_token(pkcs11_uri, pkcs11_crypt_device_callback, &data);
        if (r < 0)
                return r;

        *ret_decrypted_key = TAKE_PTR(data.decrypted_key);
        *ret_decrypted_key_size = data.decrypted_key_size;

        return 0;
}

int acquire_luks2_key(
                struct crypt_device *cd,
                const char *json,
                void *usrptr,
                const char *pin,
                char **ret_password,
                size_t *ret_password_size) {

        int r;
        size_t decrypted_key_size, encrypted_key_size;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_free_ char *pkcs11_uri = NULL;
        _cleanup_free_ void *encrypted_key = NULL;

        assert(json);
        assert(ret_password);
        assert(ret_password_size);

        r = parse_luks2_pkcs11_data(cd, json, &pkcs11_uri, &encrypted_key, &encrypted_key_size);
        if (r < 0)
                return r;

        if (usrptr) /* systemd based activation with interactive pin query callbacks */
                r = acquire_luks2_key_systemd(
                        pkcs11_uri,
                        (systemd_pkcs11_plugin_params *)usrptr,
                        encrypted_key, encrypted_key_size,
                        &decrypted_key, &decrypted_key_size);
        else /* default activation that provides single PIN if needed */
                r = acquire_luks2_key_by_pin(
                                cd, pkcs11_uri, pin,
                                encrypted_key, encrypted_key_size,
                                &decrypted_key, &decrypted_key_size);
        if (r < 0)
                return r;

        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (r < 0)
                return crypt_log_error_errno(cd, r, "Can not base64 encode key: %m");

        *ret_password = TAKE_PTR(base64_encoded);
        *ret_password_size = strlen(*ret_password);

        return 0;
}

int parse_luks2_pkcs11_data(
                struct crypt_device *cd,
                const char *json,
                char **ret_uri,
                void **ret_encrypted_key,
                size_t *ret_encrypted_key_size) {

        int r;
        size_t key_size;
        _cleanup_free_ char *uri = NULL;
        _cleanup_free_ void *key = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        JsonVariant *w;

        assert(json);
        assert(ret_uri);
        assert(ret_encrypted_key);
        assert(ret_encrypted_key_size);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return -EINVAL;

        w = json_variant_by_key(v, "pkcs11-uri");
        if (!w)
                return -EINVAL;

        uri = strdup(json_variant_string(w));
        if (!uri)
                return -ENOMEM;

        w = json_variant_by_key(v, "pkcs11-key");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), SIZE_MAX, &key, &key_size);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Failed to decode base64 encoded key.");

        *ret_uri = TAKE_PTR(uri);
        *ret_encrypted_key = TAKE_PTR(key);
        *ret_encrypted_key_size = key_size;

        return 0;
}
