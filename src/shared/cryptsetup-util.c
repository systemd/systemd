/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_LIBCRYPTSETUP
static void *cryptsetup_dl = NULL;

DLSYM_PROTOTYPE(crypt_activate_by_passphrase) = NULL;
DLSYM_PROTOTYPE(crypt_activate_by_signed_key) = NULL;
DLSYM_PROTOTYPE(crypt_activate_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_deactivate_by_name) = NULL;
DLSYM_PROTOTYPE(crypt_format) = NULL;
DLSYM_PROTOTYPE(crypt_free) = NULL;
DLSYM_PROTOTYPE(crypt_get_cipher) = NULL;
DLSYM_PROTOTYPE(crypt_get_cipher_mode) = NULL;
DLSYM_PROTOTYPE(crypt_get_data_offset) = NULL;
DLSYM_PROTOTYPE(crypt_get_device_name) = NULL;
DLSYM_PROTOTYPE(crypt_get_dir) = NULL;
DLSYM_PROTOTYPE(crypt_get_type) = NULL;
DLSYM_PROTOTYPE(crypt_get_uuid) = NULL;
DLSYM_PROTOTYPE(crypt_get_verity_info) = NULL;
DLSYM_PROTOTYPE(crypt_get_volume_key_size) = NULL;
DLSYM_PROTOTYPE(crypt_init) = NULL;
DLSYM_PROTOTYPE(crypt_init_by_name) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_add_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_destroy) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_max) = NULL;
DLSYM_PROTOTYPE(crypt_load) = NULL;
DLSYM_PROTOTYPE(crypt_resize) = NULL;
DLSYM_PROTOTYPE(crypt_resume_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_set_data_device) = NULL;
DLSYM_PROTOTYPE(crypt_set_debug_level) = NULL;
DLSYM_PROTOTYPE(crypt_set_log_callback) = NULL;
DLSYM_PROTOTYPE(crypt_set_metadata_size) = NULL;
DLSYM_PROTOTYPE(crypt_set_pbkdf_type) = NULL;
DLSYM_PROTOTYPE(crypt_suspend) = NULL;
DLSYM_PROTOTYPE(crypt_token_json_get) = NULL;
DLSYM_PROTOTYPE(crypt_token_json_set) = NULL;
DLSYM_PROTOTYPE(crypt_token_max) = NULL;
#if HAVE_CRYPT_TOKEN_SET_EXTERNAL_PATH
DLSYM_PROTOTYPE(crypt_token_set_external_path) = NULL;
#endif
DLSYM_PROTOTYPE(crypt_token_status) = NULL;
DLSYM_PROTOTYPE(crypt_volume_key_get) = NULL;
DLSYM_PROTOTYPE(crypt_reencrypt_init_by_passphrase) = NULL;
DLSYM_PROTOTYPE(crypt_reencrypt_run);
DLSYM_PROTOTYPE(crypt_metadata_locking) = NULL;
DLSYM_PROTOTYPE(crypt_set_data_offset) = NULL;
DLSYM_PROTOTYPE(crypt_header_restore) = NULL;
DLSYM_PROTOTYPE(crypt_volume_key_keyring) = NULL;

static void cryptsetup_log_glue(int level, const char *msg, void *usrptr) {

        switch (level) {
        case CRYPT_LOG_NORMAL:
                level = LOG_NOTICE;
                break;
        case CRYPT_LOG_ERROR:
                level = LOG_ERR;
                break;
        case CRYPT_LOG_VERBOSE:
                level = LOG_INFO;
                break;
        case CRYPT_LOG_DEBUG:
                level = LOG_DEBUG;
                break;
        default:
                log_error("Unknown libcryptsetup log level: %d", level);
                level = LOG_ERR;
        }

        log_full(level, "%s", msg);
}

void cryptsetup_enable_logging(struct crypt_device *cd) {
        /* It's OK to call this with a NULL parameter, in which case libcryptsetup will set the default log
         * function.
         *
         * Note that this is also called from dlopen_cryptsetup(), which we call here too. Sounds like an
         * endless loop, but isn't because we break it via the check for 'cryptsetup_dl' early in
         * dlopen_cryptsetup(). */

        if (dlopen_cryptsetup() < 0)
                return; /* If this fails, let's gracefully ignore the issue, this is just debug logging after
                         * all, and if this failed we already generated a debug log message that should help
                         * to track things down. */

        sym_crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);
        sym_crypt_set_debug_level(DEBUG_LOGGING ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);
}

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd) {

        /* With CRYPT_PBKDF_NO_BENCHMARK flag set .time_ms member is ignored
         * while .iterations must be set at least to recommended minimum value. */

        static const struct crypt_pbkdf_type minimal_pbkdf = {
                .hash = "sha512",
                .type = CRYPT_KDF_PBKDF2,
                .iterations = 1000, /* recommended minimum count for pbkdf2
                                     * according to NIST SP 800-132, ch. 5.2 */
                .flags = CRYPT_PBKDF_NO_BENCHMARK
        };

        int r;

        /* Sets a minimal PKBDF in case we already have a high entropy key. */

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = sym_crypt_set_pbkdf_type(cd, &minimal_pbkdf);
        if (r < 0)
                return r;

        return 0;
}

int cryptsetup_get_token_as_json(
                struct crypt_device *cd,
                int idx,
                const char *verify_type,
                sd_json_variant **ret) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *text;
        int r;

        assert(cd);

        /* Extracts and parses the LUKS2 JSON token data from a LUKS2 device. Optionally verifies the type of
         * the token. Returns:
         *
         *      -EINVAL → token index out of range or "type" field missing
         *      -ENOENT → token doesn't exist
         * -EMEDIUMTYPE → "verify_type" specified and doesn't match token's type
         */

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = sym_crypt_token_json_get(cd, idx, &text);
        if (r < 0)
                return r;

        r = sd_json_parse(text, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        if (verify_type) {
                sd_json_variant *w;

                w = sd_json_variant_by_key(v, "type");
                if (!w)
                        return -EINVAL;

                if (!streq_ptr(sd_json_variant_string(w), verify_type))
                        return -EMEDIUMTYPE;
        }

        if (ret)
                *ret = TAKE_PTR(v);

        return 0;
}

int cryptsetup_add_token_json(struct crypt_device *cd, sd_json_variant *v) {
        _cleanup_free_ char *text = NULL;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = sd_json_variant_format(v, 0, &text);
        if (r < 0)
                return log_debug_errno(r, "Failed to format token data for LUKS: %m");

        log_debug("Adding token text <%s>", text);

        r = sym_crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_debug_errno(r, "Failed to write token data to LUKS: %m");

        return 0;
}
#endif

int dlopen_cryptsetup(void) {
#if HAVE_LIBCRYPTSETUP
        int r;

        /* libcryptsetup added crypt_reencrypt() in 2.2.0, and marked it obsolete in 2.4.0, replacing it with
         * crypt_reencrypt_run(), which takes one extra argument but is otherwise identical. The old call is
         * still available though, and given we want to support 2.2.0 for a while longer, we'll use the old
         * symbol if the new one is not available. */

        ELF_NOTE_DLOPEN("cryptsetup",
                        "Support for disk encryption, integrity, and authentication",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libcryptsetup.so.12");

        r = dlopen_many_sym_or_warn(
                        &cryptsetup_dl, "libcryptsetup.so.12", LOG_DEBUG,
                        DLSYM_ARG(crypt_activate_by_passphrase),
                        DLSYM_ARG(crypt_activate_by_signed_key),
                        DLSYM_ARG(crypt_activate_by_volume_key),
                        DLSYM_ARG(crypt_deactivate_by_name),
                        DLSYM_ARG(crypt_format),
                        DLSYM_ARG(crypt_free),
                        DLSYM_ARG(crypt_get_cipher),
                        DLSYM_ARG(crypt_get_cipher_mode),
                        DLSYM_ARG(crypt_get_data_offset),
                        DLSYM_ARG(crypt_get_device_name),
                        DLSYM_ARG(crypt_get_dir),
                        DLSYM_ARG(crypt_get_type),
                        DLSYM_ARG(crypt_get_uuid),
                        DLSYM_ARG(crypt_get_verity_info),
                        DLSYM_ARG(crypt_get_volume_key_size),
                        DLSYM_ARG(crypt_init),
                        DLSYM_ARG(crypt_init_by_name),
                        DLSYM_ARG(crypt_keyslot_add_by_volume_key),
                        DLSYM_ARG(crypt_keyslot_destroy),
                        DLSYM_ARG(crypt_keyslot_max),
                        DLSYM_ARG(crypt_load),
                        DLSYM_ARG(crypt_resize),
                        DLSYM_ARG(crypt_resume_by_volume_key),
                        DLSYM_ARG(crypt_set_data_device),
                        DLSYM_ARG(crypt_set_debug_level),
                        DLSYM_ARG(crypt_set_log_callback),
                        DLSYM_ARG(crypt_set_metadata_size),
                        DLSYM_ARG(crypt_set_pbkdf_type),
                        DLSYM_ARG(crypt_suspend),
                        DLSYM_ARG(crypt_token_json_get),
                        DLSYM_ARG(crypt_token_json_set),
                        DLSYM_ARG(crypt_token_max),
#if HAVE_CRYPT_TOKEN_SET_EXTERNAL_PATH
                        DLSYM_ARG(crypt_token_set_external_path),
#endif
                        DLSYM_ARG(crypt_token_status),
                        DLSYM_ARG(crypt_volume_key_get),
                        DLSYM_ARG(crypt_reencrypt_init_by_passphrase),
                        DLSYM_ARG(crypt_reencrypt_run),
                        DLSYM_ARG(crypt_metadata_locking),
                        DLSYM_ARG(crypt_set_data_offset),
                        DLSYM_ARG(crypt_header_restore),
                        DLSYM_ARG(crypt_volume_key_keyring));
        if (r <= 0)
                return r;

        /* Redirect the default logging calls of libcryptsetup to our own logging infra. (Note that
         * libcryptsetup also maintains per-"struct crypt_device" log functions, which we'll also set
         * whenever allocating a "struct crypt_device" context. Why set both? To be defensive: maybe some
         * other code loaded into this process also changes the global log functions of libcryptsetup, who
         * knows? And if so, we still want our own objects to log via our own infra, at the very least.) */
        cryptsetup_enable_logging(NULL);

        const char *e = secure_getenv("SYSTEMD_CRYPTSETUP_TOKEN_PATH");
        if (e) {
#if HAVE_CRYPT_TOKEN_SET_EXTERNAL_PATH
                r = sym_crypt_token_set_external_path(e);
                if (r < 0)
                        log_debug_errno(r, "Failed to set the libcryptsetup external token path to '%s', ignoring: %m", e);
#else
                log_debug("libcryptsetup version does not support setting the external token path, not setting it to '%s'.", e);
#endif
        }

        return 1;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "cryptsetup support is not compiled in.");
#endif
}

int cryptsetup_get_keyslot_from_token(sd_json_variant *v) {
        int keyslot, r;
        sd_json_variant *w;

        /* Parses the "keyslots" field of a LUKS2 token object. The field can be an array, but here we assume
         * that it contains a single element only, since that's the only way we ever generate it
         * ourselves. */

        w = sd_json_variant_by_key(v, "keyslots");
        if (!w)
                return -ENOENT;
        if (!sd_json_variant_is_array(w) || sd_json_variant_elements(w) != 1)
                return -EMEDIUMTYPE;

        w = sd_json_variant_by_index(w, 0);
        if (!w)
                return -ENOENT;
        if (!sd_json_variant_is_string(w))
                return -EMEDIUMTYPE;

        r = safe_atoi(sd_json_variant_string(w), &keyslot);
        if (r < 0)
                return r;
        if (keyslot < 0)
                return -EINVAL;

        return keyslot;
}

const char* mangle_none(const char *s) {
        /* A helper that turns cryptsetup/integritysetup/veritysetup "options" strings into NULL if they are effectively empty */
        return isempty(s) || STR_IN_SET(s, "-", "none") ? NULL : s;
}
