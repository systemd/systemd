/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>
#include <string.h>

#include "cryptsetup-token.h"
#include "cryptsetup-token-util.h"
#include "hexdecoct.h"
#include "json.h"
#include "luks2-fido2.h"
#include "memory-util.h"
#include "version.h"

#define TOKEN_NAME "systemd-fido2"
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

        int r;
        const char *json;
        _cleanup_(erase_and_freep) char *pin_string = NULL;

        assert(!pin || pin_size);
        assert(token >= 0);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        /* Use assert_se() here to avoid emitting warning with -DNDEBUG */
        assert_se(token == r);
        assert(json);

        if (pin && memchr(pin, 0, pin_size - 1))
                return crypt_log_error_errno(cd, ENOANO, "PIN must be characters string.");

        /* pin was passed as pin = pin, pin_size = strlen(pin). We need to add terminating
         * NULL byte to addressable memory*/
        if (pin && pin[pin_size-1] != '\0') {
                pin_string = strndup(pin, pin_size);
                if (!pin_string)
                        return crypt_log_oom(cd);
        }

        return acquire_luks2_key(cd, json, (const char *)usrptr, pin_string ?: pin, password, password_len);
}

/*
 * This function is called from within following libcryptsetup calls
 * provided conditions further below are met:
 *
 * crypt_activate_by_token(), crypt_activate_by_token_type(type == 'systemd-fido2'):
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
 * prints systemd-fido2 token content in crypt_dump().
 * 'type' and 'keyslots' fields are printed by libcryptsetup
 */
_public_ void cryptsetup_token_dump(
                struct crypt_device *cd /* is always LUKS2 context */,
                const char *json /* validated 'systemd-tpm2' token if cryptsetup_token_validate is defined */) {

        int r;
        Fido2EnrollFlags required;
        size_t cid_size, salt_size;
        const char *client_pin_req_str, *up_req_str, *uv_req_str;
        _cleanup_free_ void *cid = NULL, *salt = NULL;
        _cleanup_free_ char *rp_id = NULL, *cid_str = NULL, *salt_str = NULL;

        assert(json);

        r = parse_luks2_fido2_data(cd, json, &rp_id, &salt, &salt_size, &cid, &cid_size, &required);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Failed to parse " TOKEN_NAME " metadata: %m.");

        r = crypt_dump_buffer_to_hex_string(cid, cid_size, &cid_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        r = crypt_dump_buffer_to_hex_string(salt, salt_size, &salt_str);
        if (r < 0)
                return (void) crypt_log_debug_errno(cd, r, "Can not dump " TOKEN_NAME " content: %m");

        if (required & FIDO2ENROLL_PIN)
                client_pin_req_str = "true";
        else if (required & FIDO2ENROLL_PIN_IF_NEEDED)
                client_pin_req_str = NULL;
        else
                client_pin_req_str = "false";

        if (required & FIDO2ENROLL_UP)
                up_req_str = "true";
        else if (required & FIDO2ENROLL_UP_IF_NEEDED)
                up_req_str = NULL;
        else
                up_req_str = "false";

        if (required & FIDO2ENROLL_UV)
                uv_req_str = "true";
        else if (required & FIDO2ENROLL_UV_OMIT)
                uv_req_str = NULL;
        else
                uv_req_str = "false";

        crypt_log(cd, "\tfido2-credential:" CRYPT_DUMP_LINE_SEP "%s\n", cid_str);
        crypt_log(cd, "\tfido2-salt: %s\n", salt_str);

        /* optional fields */
        if (rp_id)
                crypt_log(cd, "\tfido2-rp:   %s\n", rp_id);
        if (client_pin_req_str)
                crypt_log(cd, "\tfido2-clientPin-required:" CRYPT_DUMP_LINE_SEP "%s\n",
                          client_pin_req_str);
        if (up_req_str)
                crypt_log(cd, "\tfido2-up-required:" CRYPT_DUMP_LINE_SEP "%s\n", up_req_str);
        if (uv_req_str)
                crypt_log(cd, "\tfido2-uv-required:" CRYPT_DUMP_LINE_SEP "%s\n", uv_req_str);
}

/*
 * Note:
 *   If plugin is available in library path, it's called in before following libcryptsetup calls:
 *
 *   crypt_token_json_set, crypt_dump, any crypt_activate_by_token_* flavour
 */
_public_ int cryptsetup_token_validate(
                struct crypt_device *cd, /* is always LUKS2 context */
                const char *json /* contains valid 'type' and 'keyslots' fields. 'type' is 'systemd-tpm2' */) {

        int r;
        JsonVariant *w;
       _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert(json);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Could not parse " TOKEN_NAME " json object: %m.");

        w = json_variant_by_key(v, "fido2-credential");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "FIDO2 token data lacks 'fido2-credential' field.");
                return 1;
        }

        r = unbase64mem(json_variant_string(w), SIZE_MAX, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Invalid base64 data in 'fido2-credential' field: %m");

        w = json_variant_by_key(v, "fido2-salt");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_debug(cd, "FIDO2 token data lacks 'fido2-salt' field.");
                return 1;
        }

        r = unbase64mem(json_variant_string(w), SIZE_MAX, NULL, NULL);
        if (r < 0)
                return crypt_log_debug_errno(cd, r, "Failed to decode base64 encoded salt: %m.");

        /* The "rp" field is optional. */
        w = json_variant_by_key(v, "fido2-rp");
        if (w && !json_variant_is_string(w)) {
                crypt_log_debug(cd, "FIDO2 token data's 'fido2-rp' field is not a string.");
                return 1;
        }

        /* The "fido2-clientPin-required" field is optional. */
        w = json_variant_by_key(v, "fido2-clientPin-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_debug(cd, "FIDO2 token data's 'fido2-clientPin-required' field is not a boolean.");
                return 1;
        }

        /* The "fido2-up-required" field is optional. */
        w = json_variant_by_key(v, "fido2-up-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_debug(cd, "FIDO2 token data's 'fido2-up-required' field is not a boolean.");
                return 1;
        }

        /* The "fido2-uv-required" field is optional. */
        w = json_variant_by_key(v, "fido2-uv-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_debug(cd, "FIDO2 token data's 'fido2-uv-required' field is not a boolean.");
                return 1;
        }

        return 0;
}
