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
        size_t pin_size;
        void *encrypted_key;
        size_t encrypted_key_size;
        void *decrypted_key;
        size_t decrypted_key_size;
};

static int luks2_pkcs11_callback(
                CK_FUNCTION_LIST *m,
                CK_SESSION_HANDLE session,
                CK_SLOT_ID slot_id,
                const CK_SLOT_INFO *slot_info,
                const CK_TOKEN_INFO *token_info,
                P11KitUri *uri,
                void *userdata) {

        CK_OBJECT_HANDLE object;
        CK_RV rv;
        CK_TOKEN_INFO updated_token_info;
        int r;
        _cleanup_free_ char *token_label = NULL;
        struct luks2_pkcs11_callback_data *data = ASSERT_PTR(userdata);

        assert(m);
        assert(slot_info);
        assert(token_info);
        assert(uri);

        token_label = pkcs11_token_label(token_info);
        if (!token_label)
                return -ENOMEM;

        /* Called for every token matching our URI */
        r = pkcs11_token_login_by_pin(m, session, token_info, token_label, data->pin, data->pin_size);
        if (r == -ENOLCK) {
                /* Refresh the token info, so that we can prompt knowing the new flags if they changed. */
                rv = m->C_GetTokenInfo(slot_id, &updated_token_info);
                if (rv != CKR_OK) {
                        crypt_log_error(data->cd,
                                       "Failed to acquire updated security token information for slot %lu: %s",
                                       slot_id, sym_p11_kit_strerror(rv));
                        return -EIO;
                }
                token_info = &updated_token_info;
                r = -ENOANO;
        }

        if (r == -ENOANO) {
                if (FLAGS_SET(token_info->flags, CKF_USER_PIN_FINAL_TRY))
                        crypt_log_error(data->cd, "Please enter correct PIN for security token "
                                        "'%s' in order to unlock it (final try).", token_label);
                else if (FLAGS_SET(token_info->flags, CKF_USER_PIN_COUNT_LOW))
                        crypt_log_error(data->cd, "PIN has been entered incorrectly previously, "
                                      "please enter correct PIN for security token '%s' in order to unlock it.",
                                      token_label);
        }

        if (r == -EPERM) /* pin is locked, but map it to -ENOANO anyway */
                r = -ENOANO;

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
                const void *pin,
                size_t pin_size,
                void *encrypted_key,
                size_t encrypted_key_size,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

        int r;
        _cleanup_(luks2_pkcs11_callback_data_release) struct luks2_pkcs11_callback_data data = {
                .cd = cd,
                .pin = pin,
                .pin_size = pin_size,
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
        data.askpw_flags = params->askpw_flags;
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
                void *userdata,
                const void *pin,
                size_t pin_size,
                char **ret_password,
                size_t *ret_password_size) {

        int r;
        size_t decrypted_key_size, encrypted_key_size;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;
        _cleanup_free_ char *pkcs11_uri = NULL;
        _cleanup_free_ void *encrypted_key = NULL;
        systemd_pkcs11_plugin_params *pkcs11_params = userdata;
        ssize_t base64_encoded_size;

        assert(json);
        assert(ret_password);
        assert(ret_password_size);

        r = parse_luks2_pkcs11_data(cd, json, &pkcs11_uri, &encrypted_key, &encrypted_key_size);
        if (r < 0)
                return r;

        if (pkcs11_params && pin)
                crypt_log_verbose(cd, "PIN parameter ignored in interactive mode.");

        if (pkcs11_params) /* systemd based activation with interactive pin query callbacks */
                r = acquire_luks2_key_systemd(
                        pkcs11_uri,
                        pkcs11_params,
                        encrypted_key, encrypted_key_size,
                        &decrypted_key, &decrypted_key_size);
        else /* default activation that provides single PIN if needed */
                r = acquire_luks2_key_by_pin(
                        cd, pkcs11_uri, pin, pin_size,
                        encrypted_key, encrypted_key_size,
                        &decrypted_key, &decrypted_key_size);
        if (r < 0)
                return r;

        base64_encoded_size = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (base64_encoded_size < 0)
                return crypt_log_error_errno(cd, (int) base64_encoded_size, "Cannot base64 encode key: %m");

        *ret_password = TAKE_PTR(base64_encoded);
        *ret_password_size = base64_encoded_size;

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
                return r;

        w = json_variant_by_key(v, "pkcs11-uri");
        if (!w)
                return -EINVAL;

        uri = strdup(json_variant_string(w));
        if (!uri)
                return -ENOMEM;

        w = json_variant_by_key(v, "pkcs11-key");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), &key, &key_size);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Failed to decode base64 encoded key: %m.");

        *ret_uri = TAKE_PTR(uri);
        *ret_encrypted_key = TAKE_PTR(key);
        *ret_encrypted_key_size = key_size;

        return 0;
}
