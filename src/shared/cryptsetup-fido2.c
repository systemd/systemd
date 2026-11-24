/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ask-password-api.h"
#include "cryptsetup-fido2.h"
#include "cryptsetup-util.h"
#include "env-util.h"
#include "fido2-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "libfido2-util.h"
#include "log.h"

#include "strv.h"

void fido2_luks2_token_done(Fido2Luks2Token *t) {
        assert(t);

        iovec_done(&t->cid);
        iovec_done(&t->salt);
        t->rp_id = mfree(t->rp_id);
}

typedef struct Fido2Luks2TokenFields {
        Fido2Luks2Token token;
        int pin_required;
        int up_required;
        int uv_required;
} Fido2Luks2TokenFields;

static void fido2_luks2_token_fields_done(Fido2Luks2TokenFields *f) {
        assert(f);

        fido2_luks2_token_done(&f->token);
}

int fido2_luks2_token_parse(sd_json_variant *v, Fido2Luks2Token *ret) {
        _cleanup_(fido2_luks2_token_fields_done) Fido2Luks2TokenFields f = {
                .pin_required = -1,
                .up_required = -1,
                .uv_required = -1,
        };
        Fido2EnrollFlags required = 0;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "fido2-credential",         SD_JSON_VARIANT_STRING,  json_dispatch_unbase64_iovec, voffsetof(f, token.cid),    SD_JSON_MANDATORY },
                { "fido2-salt",               SD_JSON_VARIANT_STRING,  json_dispatch_unbase64_iovec, voffsetof(f, token.salt),   SD_JSON_MANDATORY },
                { "fido2-rp",                 SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,      voffsetof(f, token.rp_id), 0                 },
                { "fido2-clientPin-required", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,    voffsetof(f, pin_required), 0                 },
                { "fido2-up-required",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,    voffsetof(f, up_required),  0                 },
                { "fido2-uv-required",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,    voffsetof(f, uv_required),  0                 },
                {}
        };

        assert(v);
        assert(ret);

        /* Parses the JSON of a "systemd-fido2" LUKS2 token. The "fido2-rp" field and the three
         * "fido2-*-required" fields are optional. Tokens enrolled by v248 do not have the
         * "fido2-*-required" fields. For them we use the *_IF_NEEDED and *_OMIT flags. */

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &f);
        if (r < 0)
                return r;

        if (f.pin_required >= 0)
                SET_FLAG(required, FIDO2ENROLL_PIN, f.pin_required);
        else
                required |= FIDO2ENROLL_PIN_IF_NEEDED;

        if (f.up_required >= 0)
                SET_FLAG(required, FIDO2ENROLL_UP, f.up_required);
        else
                required |= FIDO2ENROLL_UP_IF_NEEDED;

        if (f.uv_required >= 0)
                SET_FLAG(required, FIDO2ENROLL_UV, f.uv_required);
        else
                required |= FIDO2ENROLL_UV_OMIT;

        f.token.required = required;
        *ret = TAKE_STRUCT(f.token);

        return 0;
}

int acquire_fido2_key(
                const char *volume_name,
                const char *friendly_name,
                const char *device,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                const char *key_file,
                size_t key_file_size,
                uint64_t key_file_offset,
                const struct iovec *key_data,
                usec_t until,
                Fido2EnrollFlags required,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

#if HAVE_LIBCRYPTSETUP && HAVE_LIBFIDO2
        _cleanup_(erase_and_freep) char *envpw = NULL;
        _cleanup_strv_free_erase_ char **pins = NULL;
        _cleanup_(iovec_done_erase) struct iovec loaded_salt = {};
        bool device_exists = false;
        struct iovec salt;
        int r;

        if ((required & (FIDO2ENROLL_PIN | FIDO2ENROLL_UP | FIDO2ENROLL_UV)) && FLAGS_SET(askpw_flags, ASK_PASSWORD_HEADLESS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOPKG),
                                        "Local verification is required to unlock this volume, but the 'headless' parameter was set.");

        assert(cid);
        assert(key_file || iovec_is_set(key_data));

        if (iovec_is_set(key_data))
                salt = *key_data;
        else {
                if (key_file_size > 0)
                        log_debug("Ignoring 'keyfile-size=' option for a FIDO2 salt file.");

                r = fido2_read_salt_file(
                                key_file, key_file_offset,
                                /* client= */ "cryptsetup",
                                /* node= */ volume_name,
                                &loaded_salt);
                if (r < 0)
                        return r;

                salt = loaded_salt;
        }

        r = getenv_steal_erase("PIN", &envpw);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire password from environment: %m");
        if (r > 0) {
                pins = strv_new(envpw);
                if (!pins)
                        return log_oom();
        }

        for (;;) {
                if (!device_exists) {
                        /* Before we inquire for the PIN we'll need, if we never talked to the device, check
                         * if the device actually is plugged in. Otherwise we'll ask for the PIN already when
                         * the device is not plugged in, which is confusing. */

                        r = fido2_have_device(device);
                        if (r < 0)
                                return r;
                        if (r == 0) /* no device found, return EAGAIN so that caller will wait/watch udev */
                                return -EAGAIN;

                        device_exists = true;  /* now we know for sure, a device exists, no need to ask again */
                }

                /* Always make an attempt before asking for PIN.
                 * fido2_use_hmac_hash() will perform a pre-flight check for whether the credential for
                 * can be found on one of the connected devices. This way, we can avoid prompting the user
                 * for a PIN when we are sure that no device can be used. */
                r = fido2_use_hmac_hash(
                                device,
                                rp_id ?: "io.systemd.cryptsetup",
                                salt.iov_base, salt.iov_len,
                                cid, cid_size,
                                /* public_key= */ NULL,
                                /* public_key_algorithm= */ NULL,
                                pins,
                                required,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (!IN_SET(r,
                            -ENOANO,   /* needs pin */
                            -ENOLCK))  /* pin incorrect */
                        return r;

                device_exists = true; /* that a PIN is needed/wasn't correct means that we managed to
                                       * talk to a device */

                if (FLAGS_SET(askpw_flags, ASK_PASSWORD_HEADLESS))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOPKG), "PIN querying disabled via 'headless' option. Use the '$PIN' environment variable.");

                AskPasswordRequest req = {
                        .tty_fd = -EBADF,
                        .message = "Please enter security token PIN:",
                        .icon = "drive-harddisk",
                        .keyring = "fido2-pin",
                        .credential = "cryptsetup.fido2-pin",
                        .until = until,
                        .hup_fd = -EBADF,
                };

                pins = strv_free_erase(pins);
                r = ask_password_auto(&req, askpw_flags, &pins);
                if (r < 0)
                        return log_error_errno(r, "Failed to ask for user password: %m");

                askpw_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;
        }
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "FIDO2 token support not available.");
#endif
}

int acquire_fido2_key_auto(
                struct crypt_device *cd,
                const char *name,
                const char *friendly_name,
                const char *fido2_device,
                usec_t until,
                const char *askpw_credential,
                AskPasswordFlags askpw_flags,
                void **ret_decrypted_key,
                size_t *ret_decrypted_key_size) {

#if HAVE_LIBCRYPTSETUP && HAVE_LIBFIDO2
        bool found = false;
        int r, ret = -ENOENT;

        assert(cd);
        assert(name);
        assert(ret_decrypted_key);
        assert(ret_decrypted_key_size);

        /* Loads FIDO2 metadata from LUKS2 JSON token headers. */

        for (int token = 0; token < sym_crypt_token_max(CRYPT_LUKS2); token++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                _cleanup_(fido2_luks2_token_done) Fido2Luks2Token t = {};
                int ks;

                r = cryptsetup_get_token_as_json(cd, token, "systemd-fido2", &v);
                if (ERRNO_IS_NEG_CRYPTSETUP_TOKEN_SKIP(r))
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read JSON token data off disk: %m");

                ks = cryptsetup_get_keyslot_from_token(v);
                if (ks == -ENOMEM)
                        return log_oom();
                if (ks < 0) {
                        /* Handle parsing errors of the keyslots field gracefully, since it's not 'owned' by
                         * us, but by the LUKS2 spec */
                        log_warning_errno(ks, "Failed to extract keyslot index from FIDO2 JSON data token %i, skipping: %m", token);
                        continue;
                }

                r = fido2_luks2_token_parse(v, &t);
                if (r == -ENXIO) /* A mandatory field is missing, i.e. the token is broken */
                        r = -EBADMSG; /* Do not return -ENXIO here, as callers use it to indicate that no
                                       * FIDO2 token is enrolled at all. */
                if (r < 0)
                        return log_error_errno(r, "Failed to parse FIDO2 JSON data token %i: %m", token);

                found = true;

                ret = acquire_fido2_key(
                                name,
                                friendly_name,
                                fido2_device,
                                t.rp_id,
                                t.cid.iov_base, t.cid.iov_len,
                                /* key_file= */ NULL, /* salt is read from LUKS header instead of key_file */
                                /* key_file_size= */ 0,
                                /* key_file_offset= */ 0,
                                &t.salt,
                                until,
                                t.required,
                                "cryptsetup.fido2-pin",
                                askpw_flags,
                                ret_decrypted_key,
                                ret_decrypted_key_size);
                if (ret == 0)
                        break;
        }

        if (!found) /* Callers decide whether this is an error, or whether they fall back to something else */
                return log_debug_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "No valid FIDO2 token data found.");

        if (ret == -EAGAIN) /* fido2 device does not exist, or UV is blocked; caller will prompt for retry */
                return log_debug_errno(ret, "FIDO2 token does not exist, or UV is blocked.");
        if (ret < 0)
                return log_error_errno(ret, "Failed to unlock LUKS volume with FIDO2 token: %m");

        log_info("Unlocked volume via automatically discovered security FIDO2 token.");
        return ret;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "FIDO2 token support not available.");
#endif
}
