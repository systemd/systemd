/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "json-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_LIBCRYPTSETUP
DLSYM_PROTOTYPE(crypt_activate_by_passphrase) = NULL;
DLSYM_PROTOTYPE(crypt_activate_by_signed_key) = NULL;
DLSYM_PROTOTYPE(crypt_activate_by_token_pin) = NULL;
DLSYM_PROTOTYPE(crypt_activate_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_deactivate) = NULL;
DLSYM_PROTOTYPE(crypt_deactivate_by_name) = NULL;
DLSYM_PROTOTYPE(crypt_format) = NULL;
DLSYM_PROTOTYPE(crypt_free) = NULL;
DLSYM_PROTOTYPE(crypt_get_cipher) = NULL;
DLSYM_PROTOTYPE(crypt_get_cipher_mode) = NULL;
DLSYM_PROTOTYPE(crypt_get_data_offset) = NULL;
DLSYM_PROTOTYPE(crypt_get_device_name) = NULL;
DLSYM_PROTOTYPE(crypt_get_dir) = NULL;
DLSYM_PROTOTYPE(crypt_get_pbkdf_type_params) = NULL;
DLSYM_PROTOTYPE(crypt_get_type) = NULL;
DLSYM_PROTOTYPE(crypt_get_uuid) = NULL;
DLSYM_PROTOTYPE(crypt_get_verity_info) = NULL;
DLSYM_PROTOTYPE(crypt_get_volume_key_size) = NULL;
DLSYM_PROTOTYPE(crypt_header_restore) = NULL;
DLSYM_PROTOTYPE(crypt_init) = NULL;
DLSYM_PROTOTYPE(crypt_init_by_name) = NULL;
DLSYM_PROTOTYPE(crypt_init_data_device) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_add_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_destroy) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_max) = NULL;
DLSYM_PROTOTYPE(crypt_keyslot_status) = NULL;
DLSYM_PROTOTYPE(crypt_load) = NULL;
DLSYM_PROTOTYPE(crypt_logf) = NULL;
DLSYM_PROTOTYPE(crypt_metadata_locking) = NULL;
DLSYM_PROTOTYPE(crypt_persistent_flags_get) = NULL;
DLSYM_PROTOTYPE(crypt_persistent_flags_set) = NULL;
DLSYM_PROTOTYPE(crypt_reencrypt_init_by_passphrase) = NULL;
DLSYM_PROTOTYPE(crypt_reencrypt_run);
DLSYM_PROTOTYPE(crypt_resize) = NULL;
DLSYM_PROTOTYPE(crypt_resume_by_volume_key) = NULL;
DLSYM_PROTOTYPE(crypt_set_data_device) = NULL;
DLSYM_PROTOTYPE(crypt_set_data_offset) = NULL;
DLSYM_PROTOTYPE(crypt_set_debug_level) = NULL;
static int missing_crypt_set_keyring_to_link(
                struct crypt_device *cd,
                const char *key_description,
                const char *old_key_description,
                const char *key_type_desc,
                const char *keyring_to_link_vk) {
        return -ENOSYS;
}
DLSYM_PROTOTYPE(crypt_set_keyring_to_link) = missing_crypt_set_keyring_to_link;
DLSYM_PROTOTYPE(crypt_set_log_callback) = NULL;
DLSYM_PROTOTYPE(crypt_set_metadata_size) = NULL;
DLSYM_PROTOTYPE(crypt_set_pbkdf_type) = NULL;
DLSYM_PROTOTYPE(crypt_status) = NULL;
DLSYM_PROTOTYPE(crypt_suspend) = NULL;
DLSYM_PROTOTYPE(crypt_token_external_path) = NULL;
DLSYM_PROTOTYPE(crypt_token_json_get) = NULL;
DLSYM_PROTOTYPE(crypt_token_json_set) = NULL;
DLSYM_PROTOTYPE(crypt_token_max) = NULL;
static int missing_crypt_token_set_external_path(const char *path) {
        return -ENOSYS;
}
DLSYM_PROTOTYPE(crypt_token_set_external_path) = missing_crypt_token_set_external_path;
DLSYM_PROTOTYPE(crypt_token_status) = NULL;
DLSYM_PROTOTYPE(crypt_volume_key_get) = NULL;
DLSYM_PROTOTYPE(crypt_volume_key_keyring) = NULL;
DLSYM_PROTOTYPE(crypt_wipe) = NULL;
DLSYM_PROTOTYPE(crypt_get_integrity_info) = NULL;

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

        if (dlopen_cryptsetup(LOG_DEBUG) < 0)
                return; /* If this fails, let's gracefully ignore the issue, this is just debug logging after
                         * all, and if this failed we already generated a debug log message that should help
                         * to track things down. */

        sym_crypt_set_log_callback(cd, cryptsetup_log_glue, /* usrptr= */ NULL);
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
         *     -EUCLEAN → token JSON data cannot be parsed
         */

        r = sym_crypt_token_json_get(cd, idx, &text);
        if (r < 0)
                return r;

        r = sd_json_parse(text, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
        if (r < 0)
                return r == -ENOMEM ? r : -EUCLEAN; /* Report unparseable token data in a single way for callers to skip */

        if (verify_type) {
                const char *type = NULL;

                static const sd_json_dispatch_field dispatch_table[] = {
                        { "type", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                        {}
                };

                r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &type);
                if (r == -ENXIO)
                        return -EINVAL;
                if (r < 0 || !streq(type, verify_type))
                        return -EMEDIUMTYPE;
        }

        if (ret)
                *ret = TAKE_PTR(v);

        return 0;
}

int cryptsetup_add_token_json(struct crypt_device *cd, sd_json_variant *v) {
        _cleanup_free_ char *text = NULL;
        int r;

        r = sd_json_variant_format(v, /* flags= */ 0, &text);
        if (r < 0)
                return log_debug_errno(r, "Failed to format token data for LUKS: %m");

        log_debug("Adding token text <%s>", text);

        r = sym_crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_debug_errno(r, "Failed to write token data to LUKS: %m");

        return 0;
}

int cryptsetup_get_volume_key_prefix(
                struct crypt_device *cd,
                const char *volume_name,
                char **ret) {

        _cleanup_free_ char *volume = NULL;
        const char *uuid;
        char *s;

        assert(ret);

        uuid = sym_crypt_get_uuid(cd);
        if (!uuid)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to get LUKS UUID.");

        if (volume_name)
                /* avoid ambiguity around ":" once we join things below */
                volume = xescape(volume_name, ":");
        else
                volume = strjoin("luks-", uuid);
        if (!volume)
                return log_oom_debug();

        s = strjoin("cryptsetup:", volume, ":", uuid);
        if (!s)
                return log_oom_debug();

        *ret = s;

        return 0;
}

/* The hash must match what measure_volume_key() extends to the SHA256 bank of the TPM2. */
int cryptsetup_get_volume_key_id(
                struct crypt_device *cd,
                const char *volume_name,
                const void *volume_key,
                size_t volume_key_size,
                char **ret) {

        _cleanup_free_ char *prefix = NULL;
        uint8_t digest[SHA256_DIGEST_SIZE];
        char *hex;
        int r;

        assert(ret);

        r = cryptsetup_get_volume_key_prefix(cd, volume_name, &prefix);
        if (r < 0)
                return log_debug_errno(r, "Failed to get LUKS volume key prefix.");

        hmac_sha256(volume_key, volume_key_size, prefix, strlen(prefix), digest);

        hex = hexmem(digest, sizeof(digest));
        if (!hex)
                return log_oom_debug();

        *ret = hex;

        return 0;
}
#endif

int dlopen_cryptsetup(int log_level) {
#if HAVE_LIBCRYPTSETUP
        static void *cryptsetup_dl = NULL;
        int r;

        /* libcryptsetup added crypt_reencrypt() in 2.2.0, and marked it obsolete in 2.4.0, replacing it with
         * crypt_reencrypt_run(), which takes one extra argument but is otherwise identical. The old call is
         * still available though, and given we want to support 2.2.0 for a while longer, we'll use the old
         * symbol if the new one is not available. */

        LIBCRYPTSETUP_NOTE(suggested);

        r = dlopen_many_sym_or_warn(
                        &cryptsetup_dl, "libcryptsetup.so.12", log_level,
                        DLSYM_ARG(crypt_activate_by_passphrase),
                        DLSYM_ARG(crypt_activate_by_signed_key),
                        DLSYM_ARG(crypt_activate_by_token_pin),
                        DLSYM_ARG(crypt_activate_by_volume_key),
                        DLSYM_ARG(crypt_deactivate),
                        DLSYM_ARG(crypt_deactivate_by_name),
                        DLSYM_ARG(crypt_format),
                        DLSYM_ARG(crypt_free),
                        DLSYM_ARG(crypt_get_cipher),
                        DLSYM_ARG(crypt_get_cipher_mode),
                        DLSYM_ARG(crypt_get_data_offset),
                        DLSYM_ARG(crypt_get_device_name),
                        DLSYM_ARG(crypt_get_dir),
                        DLSYM_ARG(crypt_get_pbkdf_type_params),
                        DLSYM_ARG(crypt_get_type),
                        DLSYM_ARG(crypt_get_uuid),
                        DLSYM_ARG(crypt_get_verity_info),
                        DLSYM_ARG(crypt_get_volume_key_size),
                        DLSYM_ARG(crypt_header_restore),
                        DLSYM_ARG(crypt_init),
                        DLSYM_ARG(crypt_init_by_name),
                        DLSYM_ARG(crypt_init_data_device),
                        DLSYM_ARG(crypt_keyslot_add_by_volume_key),
                        DLSYM_ARG(crypt_keyslot_destroy),
                        DLSYM_ARG(crypt_keyslot_max),
                        DLSYM_ARG(crypt_keyslot_status),
                        DLSYM_ARG(crypt_load),
                        DLSYM_ARG(crypt_logf),
                        DLSYM_ARG(crypt_metadata_locking),
                        DLSYM_ARG(crypt_persistent_flags_get),
                        DLSYM_ARG(crypt_persistent_flags_set),
                        DLSYM_ARG(crypt_reencrypt_init_by_passphrase),
                        DLSYM_ARG(crypt_reencrypt_run),
                        DLSYM_ARG(crypt_resize),
                        DLSYM_ARG(crypt_resume_by_volume_key),
                        DLSYM_ARG(crypt_set_data_device),
                        DLSYM_ARG(crypt_set_data_offset),
                        DLSYM_ARG(crypt_set_debug_level),
                        DLSYM_ARG(crypt_set_log_callback),
                        DLSYM_ARG(crypt_set_metadata_size),
                        DLSYM_ARG(crypt_set_pbkdf_type),
                        DLSYM_ARG(crypt_status),
                        DLSYM_ARG(crypt_suspend),
                        DLSYM_ARG(crypt_token_external_path),
                        DLSYM_ARG(crypt_token_json_get),
                        DLSYM_ARG(crypt_token_json_set),
                        DLSYM_ARG(crypt_token_max),
                        DLSYM_ARG(crypt_token_status),
                        DLSYM_ARG(crypt_volume_key_get),
                        DLSYM_ARG(crypt_volume_key_keyring),
                        DLSYM_ARG(crypt_wipe),
                        DLSYM_ARG(crypt_get_integrity_info));
        if (r <= 0)
                return r;

        /* Optional symbols: present in libcryptsetup 2.7+ only. If unresolved, the prototype keeps its
         * static initializer pointing at a fallback that returns -ENOSYS, so call sites can invoke the
         * symbol unconditionally. */
        DLSYM_OPTIONAL(cryptsetup_dl, crypt_set_keyring_to_link);
        DLSYM_OPTIONAL(cryptsetup_dl, crypt_token_set_external_path);

        /* Redirect the default logging calls of libcryptsetup to our own logging infra. (Note that
         * libcryptsetup also maintains per-"struct crypt_device" log functions, which we'll also set
         * whenever allocating a "struct crypt_device" context. Why set both? To be defensive: maybe some
         * other code loaded into this process also changes the global log functions of libcryptsetup, who
         * knows? And if so, we still want our own objects to log via our own infra, at the very least.) */
        cryptsetup_enable_logging(/* cd= */ NULL);

        const char *e = secure_getenv("SYSTEMD_CRYPTSETUP_TOKEN_PATH");
        if (e) {
                r = sym_crypt_token_set_external_path(e);
                if (r == -ENOSYS)
                        log_debug("Loaded libcryptsetup does not support setting the external token path, not setting it to '%s'.", e);
                else if (r < 0)
                        log_debug_errno(r, "Failed to set the libcryptsetup external token path to '%s', ignoring: %m", e);
        }

        return 1;
#else
        return log_full_errno(log_level, SYNTHETIC_ERRNO(EOPNOTSUPP),
                              "libcryptsetup support is not compiled in.");
#endif
}

typedef struct CryptsetupTokenKeyslots {
        int *keyslots;
        size_t n_keyslots;
} CryptsetupTokenKeyslots;

static int dispatch_token_keyslots(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        CryptsetupTokenKeyslots *k = ASSERT_PTR(userdata);
        sd_json_variant *i;
        int r;

        /* The "keyslots" field is an array of key slot numbers, written as strings */

        if (!sd_json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EMEDIUMTYPE), "JSON field '%s' is not an array.", strna(name));

        JSON_VARIANT_ARRAY_FOREACH(i, variant) {
                int keyslot;

                if (!sd_json_variant_is_string(i))
                        return json_log(i, flags, SYNTHETIC_ERRNO(EMEDIUMTYPE), "JSON field '%s' contains an element that is not a string.", strna(name));

                r = safe_atoi(sd_json_variant_string(i), &keyslot);
                if (r < 0)
                        return json_log(i, flags, r, "JSON field '%s' contains an element that is not a number: %m", strna(name));
                if (keyslot < 0)
                        return json_log(i, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' contains a negative key slot.", strna(name));

                if (!GREEDY_REALLOC(k->keyslots, k->n_keyslots + 1))
                        return json_log_oom(i, flags);

                k->keyslots[k->n_keyslots++] = keyslot;
        }

        return 0;
}

int cryptsetup_token_parse_common(
                sd_json_variant *v,
                const char **ret_type,
                int **ret_keyslots,
                size_t *ret_n_keyslots) {

        struct {
                const char *type;
                CryptsetupTokenKeyslots keyslots;
        } p = {};
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "type",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, type),     SD_JSON_MANDATORY },
                { "keyslots", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_token_keyslots,       voffsetof(p, keyslots), SD_JSON_MANDATORY },
                {}
        };

        assert(v);

        /* Parses the "type" and "keyslots" fields that every LUKS2 token has. They are defined by the LUKS2
         * spec, not by us. The returned type string is owned by the JSON variant. */

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0) {
                free(p.keyslots.keyslots);
                return r;
        }

        if (ret_type)
                *ret_type = p.type;
        if (ret_n_keyslots)
                *ret_n_keyslots = p.keyslots.n_keyslots;
        if (ret_keyslots)
                *ret_keyslots = TAKE_PTR(p.keyslots.keyslots);
        else
                free(p.keyslots.keyslots);

        return 0;
}

int cryptsetup_get_keyslot_from_token(sd_json_variant *v) {
        _cleanup_free_ int *keyslots = NULL;
        size_t n_keyslots;
        int r;

        /* Parses the "keyslots" field of a LUKS2 token object. The field can be an array, but here we assume
         * that it contains a single element only, since that's the only way we ever generate it
         * ourselves. */

        r = cryptsetup_token_parse_common(v, /* ret_type= */ NULL, &keyslots, &n_keyslots);
        if (r == -ENXIO)
                return -ENOENT;
        if (r < 0)
                return r;
        if (n_keyslots != 1)
                return -EMEDIUMTYPE;

        return keyslots[0];
}

const char* mangle_none(const char *s) {
        /* A helper that turns cryptsetup/integritysetup/veritysetup "options" strings into NULL if they are effectively empty */
        return isempty(s) || STR_IN_SET(s, "-", "none") ? NULL : s;
}
