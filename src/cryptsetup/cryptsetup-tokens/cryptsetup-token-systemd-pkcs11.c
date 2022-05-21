/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "cryptsetup-token-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "luks2-pkcs11.h"
#include "memory-util.h"
#include "pkcs11-util.h"
#include "version.h"

#define TOKEN_NAME "systemd-pkcs11"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {
        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR " systemd-v" STRINGIFY(PROJECT_VERSION) " (" GIT_VERSION ")";
}

_public_ int cryptsetup_token_open_pin(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                const char *pin,
                size_t pin_size,
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        const char *json;
        int r;

        assert(!pin || pin_size);
        assert(token >= 0);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        /* Use assert_se() here to avoid emitting warning with -DNDEBUG */
        assert_se(token == r);
        assert(json);

        return acquire_luks2_key(cd, json, usrptr, pin, pin_size, password, password_len);
}

/*
 * This function is called from within following libcryptsetup calls
 * provided conditions further below are met:
 *
 * crypt_activate_by_token(), crypt_activate_by_token_type(type == 'systemd-pkcs11'):
 *
 * - token is assigned to at least one luks2 keyslot eligible to activate LUKS2 device
 *   (alternatively: name is set to null, flags contains CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY
 *    and token is assigned to at least single keyslot).
 *
 * - if plugin defines validate function (see cryptsetup_token_validate below) it must have
 *   passed the check (aka return 0)
 */
_public_ int cryptsetup_token_open(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        return cryptsetup_token_open_pin(cd, token, NULL, 0, password, password_len, usrptr);
}

/*
 * libcryptsetup callback for memory deallocation of 'password' parameter passed in
 * any crypt_token_open_* plugin function
 */
_public_ void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len) {
        erase_and_free(buffer);
}

/*
 * prints systemd-pkcs11 token content in crypt_dump().
 * 'type' and 'keyslots' fields are printed by libcryptsetup
 */
_public_ void cryptsetup_token_dump(
                struct crypt_device *cd /* is always LUKS2 context */,
                const char *json /* validated 'systemd-pkcs11' token if cryptsetup_token_validate is defined */) {

        int r;
        size_t pkcs11_key_size;
        _cleanup_free_ char *pkcs11_uri = NULL, *key_str = NULL;
        _cleanup_free_ void *pkcs11_key = NULL;

        r = parse_luks2_pkcs11_data(cd, json, &pkcs11_uri, &pkcs11_key, &pkcs11_key_size);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " metadata: %m.");

        r = crypt_dump_buffer_to_hex_string(pkcs11_key, pkcs11_key_size, &key_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        crypt_log(cd, "\tpkcs11-uri: %s\n", pkcs11_uri);
        crypt_log(cd, "\tpkcs11-key: %s\n", key_str);
}

/*
 * Note:
 *   If plugin is available in library path, it's called in before following libcryptsetup calls:
 *
 *   crypt_token_json_set, crypt_dump, any crypt_activate_by_token_* flavour
 */
_public_ int cryptsetup_token_validate(
                struct crypt_device *cd, /* is always LUKS2 context */
                const char *json /* contains valid 'type' and 'keyslots' fields. 'type' is 'systemd-pkcs11' */) {

        int r;
        JsonVariant *w;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Could not parse " TOKEN_NAME " json object: %m.");

        w = json_variant_by_key(v, "pkcs11-uri");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "PKCS#11 token data lacks 'pkcs11-uri' field.");
                return 1;
        }

        if (!pkcs11_uri_valid(json_variant_string(w))) {
                crypt_log_debug(cd, "PKCS#11 token data contains invalid PKCS#11 URI.");
                return 1;
        }

        w = json_variant_by_key(v, "pkcs11-key");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "PKCS#11 token data lacks 'pkcs11-key' field.");
                return 1;
        }

        r = unbase64mem(json_variant_string(w), SIZE_MAX, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Failed to decode base64 encoded key: %m.");

        return 0;
}
