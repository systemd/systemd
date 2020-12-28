/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBCRYPTSETUP
#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "log.h"
#include "parse-util.h"

static void *cryptsetup_dl = NULL;

int (*sym_crypt_activate_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
int (*sym_crypt_activate_by_signed_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, const char *signature, size_t signature_size, uint32_t flags);
#endif
int (*sym_crypt_activate_by_volume_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, uint32_t flags);
int (*sym_crypt_deactivate_by_name)(struct crypt_device *cd, const char *name, uint32_t flags);
int (*sym_crypt_format)(struct crypt_device *cd, const char *type, const char *cipher, const char *cipher_mode, const char *uuid, const char *volume_key, size_t volume_key_size, void *params);
void (*sym_crypt_free)(struct crypt_device *cd);
const char *(*sym_crypt_get_dir)(void);
int (*sym_crypt_get_verity_info)(struct crypt_device *cd, struct crypt_params_verity *vp);
int (*sym_crypt_init)(struct crypt_device **cd, const char *device);
int (*sym_crypt_init_by_name)(struct crypt_device **cd, const char *name);
int (*sym_crypt_keyslot_add_by_volume_key)(struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
int (*sym_crypt_load)(struct crypt_device *cd, const char *requested_type, void *params);
int (*sym_crypt_resize)(struct crypt_device *cd, const char *name, uint64_t new_size);
int (*sym_crypt_set_data_device)(struct crypt_device *cd, const char *device);
void (*sym_crypt_set_debug_level)(int level);
void (*sym_crypt_set_log_callback)(struct crypt_device *cd, void (*log)(int level, const char *msg, void *usrptr), void *usrptr);
int (*sym_crypt_set_pbkdf_type)(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf) = NULL;
int (*sym_crypt_token_json_get)(struct crypt_device *cd, int token, const char **json) = NULL;
int (*sym_crypt_token_json_set)(struct crypt_device *cd, int token, const char *json) = NULL;
int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);
#if HAVE_CRYPT_TOKEN_MAX
int (*sym_crypt_token_max)(const char *type);
#endif

int dlopen_cryptsetup(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (cryptsetup_dl)
                return 0; /* Already loaded */

        dl = dlopen("libcryptsetup.so.12", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libcryptsetup support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(crypt_activate_by_passphrase),
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        DLSYM_ARG(crypt_activate_by_signed_key),
#endif
                        DLSYM_ARG(crypt_activate_by_volume_key),
                        DLSYM_ARG(crypt_deactivate_by_name),
                        DLSYM_ARG(crypt_format),
                        DLSYM_ARG(crypt_free),
                        DLSYM_ARG(crypt_get_dir),
                        DLSYM_ARG(crypt_get_verity_info),
                        DLSYM_ARG(crypt_init),
                        DLSYM_ARG(crypt_init_by_name),
                        DLSYM_ARG(crypt_keyslot_add_by_volume_key),
                        DLSYM_ARG(crypt_load),
                        DLSYM_ARG(crypt_resize),
                        DLSYM_ARG(crypt_set_data_device),
                        DLSYM_ARG(crypt_set_debug_level),
                        DLSYM_ARG(crypt_set_log_callback),
                        DLSYM_ARG(crypt_set_pbkdf_type),
                        DLSYM_ARG(crypt_token_json_get),
                        DLSYM_ARG(crypt_token_json_set),
                        DLSYM_ARG(crypt_volume_key_get),
#if HAVE_CRYPT_TOKEN_MAX
                        DLSYM_ARG(crypt_token_max),
#endif
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        cryptsetup_dl = TAKE_PTR(dl);
        return 1;
}

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
        if (!cd)
                return;

        if (dlopen_cryptsetup() < 0) /* If this fails, let's gracefully ignore the issue, this is just debug
                                      * logging after all, and if this failed we already generated a debug
                                      * log message that should help to track things down. */
                return;

        sym_crypt_set_log_callback(cd, cryptsetup_log_glue, NULL);
        sym_crypt_set_debug_level(DEBUG_LOGGING ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);
}

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd) {

        static const struct crypt_pbkdf_type minimal_pbkdf = {
                .hash = "sha512",
                .type = CRYPT_KDF_PBKDF2,
                .iterations = 1,
                .time_ms = 1,
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
                JsonVariant **ret) {

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
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

        r = json_parse(text, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        if (verify_type) {
                JsonVariant *w;

                w = json_variant_by_key(v, "type");
                if (!w)
                        return -EINVAL;

                if (!streq_ptr(json_variant_string(w), verify_type))
                        return -EMEDIUMTYPE;
        }

        if (ret)
                *ret = TAKE_PTR(v);

        return 0;
}

int cryptsetup_get_keyslot_from_token(JsonVariant *v) {
        int keyslot, r;
        JsonVariant *w;

        /* Parses the "keyslots" field of a LUKS2 token object. The field can be an array, but here we assume
         * that it contains a single element only, since that's the only way we ever generate it
         * ourselves. */

        w = json_variant_by_key(v, "keyslots");
        if (!w)
                return -ENOENT;
        if (!json_variant_is_array(w) || json_variant_elements(w) != 1)
                return -EMEDIUMTYPE;

        w = json_variant_by_index(w, 0);
        if (!w)
                return -ENOENT;
        if (!json_variant_is_string(w))
                return -EMEDIUMTYPE;

        r = safe_atoi(json_variant_string(w), &keyslot);
        if (r < 0)
                return r;
        if (keyslot < 0)
                return -EINVAL;

        return keyslot;
}

int cryptsetup_add_token_json(struct crypt_device *cd, JsonVariant *v) {
        _cleanup_free_ char *text = NULL;
        int r;

        r = dlopen_cryptsetup();
        if (r < 0)
                return r;

        r = json_variant_format(v, 0, &text);
        if (r < 0)
                return log_debug_errno(r, "Failed to format token data for LUKS: %m");

        log_debug("Adding token text <%s>", text);

        r = sym_crypt_token_json_set(cd, CRYPT_ANY_TOKEN, text);
        if (r < 0)
                return log_debug_errno(r, "Failed to write token data to LUKS: %m");

        return 0;
}
#endif
