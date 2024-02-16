/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "log.h"
#include "parse-util.h"

#if HAVE_LIBCRYPTSETUP
static void *cryptsetup_dl = NULL;

int (*sym_crypt_activate_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
int (*sym_crypt_activate_by_signed_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, const char *signature, size_t signature_size, uint32_t flags);
#endif
int (*sym_crypt_activate_by_volume_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, uint32_t flags);
int (*sym_crypt_deactivate_by_name)(struct crypt_device *cd, const char *name, uint32_t flags);
int (*sym_crypt_format)(struct crypt_device *cd, const char *type, const char *cipher, const char *cipher_mode, const char *uuid, const char *volume_key, size_t volume_key_size, void *params);
void (*sym_crypt_free)(struct crypt_device *cd);
const char *(*sym_crypt_get_cipher)(struct crypt_device *cd);
const char *(*sym_crypt_get_cipher_mode)(struct crypt_device *cd);
uint64_t (*sym_crypt_get_data_offset)(struct crypt_device *cd);
const char *(*sym_crypt_get_device_name)(struct crypt_device *cd);
const char *(*sym_crypt_get_dir)(void);
const char *(*sym_crypt_get_type)(struct crypt_device *cd);
const char *(*sym_crypt_get_uuid)(struct crypt_device *cd);
int (*sym_crypt_get_verity_info)(struct crypt_device *cd, struct crypt_params_verity *vp);
int (*sym_crypt_get_volume_key_size)(struct crypt_device *cd);
int (*sym_crypt_init)(struct crypt_device **cd, const char *device);
int (*sym_crypt_init_by_name)(struct crypt_device **cd, const char *name);
int (*sym_crypt_keyslot_add_by_volume_key)(struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
int (*sym_crypt_keyslot_destroy)(struct crypt_device *cd, int keyslot);
int (*sym_crypt_keyslot_max)(const char *type);
int (*sym_crypt_load)(struct crypt_device *cd, const char *requested_type, void *params);
int (*sym_crypt_resize)(struct crypt_device *cd, const char *name, uint64_t new_size);
int (*sym_crypt_resume_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size);
int (*sym_crypt_set_data_device)(struct crypt_device *cd, const char *device);
void (*sym_crypt_set_debug_level)(int level);
void (*sym_crypt_set_log_callback)(struct crypt_device *cd, void (*log)(int level, const char *msg, void *usrptr), void *usrptr);
#if HAVE_CRYPT_SET_METADATA_SIZE
int (*sym_crypt_set_metadata_size)(struct crypt_device *cd, uint64_t metadata_size, uint64_t keyslots_size);
#endif
int (*sym_crypt_set_pbkdf_type)(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf);
int (*sym_crypt_suspend)(struct crypt_device *cd, const char *name);
int (*sym_crypt_token_json_get)(struct crypt_device *cd, int token, const char **json);
int (*sym_crypt_token_json_set)(struct crypt_device *cd, int token, const char *json);
#if HAVE_CRYPT_TOKEN_MAX
int (*sym_crypt_token_max)(const char *type);
#endif
crypt_token_info (*sym_crypt_token_status)(struct crypt_device *cd, int token, const char **type);
int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);
#if HAVE_CRYPT_REENCRYPT_INIT_BY_PASSPHRASE
int (*sym_crypt_reencrypt_init_by_passphrase)(struct crypt_device *cd, const char *name, const char *passphrase, size_t passphrase_size, int keyslot_old, int keyslot_new, const char *cipher, const char *cipher_mode, const struct crypt_params_reencrypt *params);
#endif
#if HAVE_CRYPT_REENCRYPT
int (*sym_crypt_reencrypt)(struct crypt_device *cd, int (*progress)(uint64_t size, uint64_t offset, void *usrptr));
#endif
int (*sym_crypt_metadata_locking)(struct crypt_device *cd, int enable);
#if HAVE_CRYPT_SET_DATA_OFFSET
int (*sym_crypt_set_data_offset)(struct crypt_device *cd, uint64_t data_offset);
#endif
int (*sym_crypt_header_restore)(struct crypt_device *cd, const char *requested_type, const char *backup_file);
int (*sym_crypt_volume_key_keyring)(struct crypt_device *cd, int enable);

/* Unfortunately libcryptsetup provides neither an environment variable to redirect where to look for token
 * modules, nor does it have an API to change the token lookup path at runtime. The maintainers suggest using
 * ELF interposition instead (see https://gitlab.com/cryptsetup/cryptsetup/-/issues/846). Hence let's do
 * that: let's interpose libcryptsetup's crypt_token_external_path() function with our own, that *does*
 * honour an environment variable where to look for tokens. This is tremendously useful for debugging
 * libcryptsetup tokens: set the environment variable to your build dir and you can easily test token modules
 * without jumping through various hoops. */

/* Do this only on new enough compilers that actually support the "symver" attribute. Given this is a debug
 * feature, let's simply not bother on older compilers */
#if BUILD_MODE_DEVELOPER && defined(__has_attribute) && __has_attribute(symver)
const char *my_crypt_token_external_path(void); /* prototype for our own implementation */

/* We use the "symver" attribute to mark this implementation as the default implementation, and drop the
 * SD_SHARED namespace we by default attach to our symbols via a version script. */
__attribute__((symver("crypt_token_external_path@@")))
_public_ const char *my_crypt_token_external_path(void) {
        const char *e;

        e = secure_getenv("SYSTEMD_CRYPTSETUP_TOKEN_PATH");
        if (e)
                return e;

        /* Now chain invoke the original implementation. */
        if (cryptsetup_dl) {
                typeof(crypt_token_external_path) *func;
                func = (typeof(crypt_token_external_path)*) dlsym(cryptsetup_dl, "crypt_token_external_path");
                if (func)
                        return func();
        }

        return NULL;
}
#endif

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

int dlopen_cryptsetup(void) {
#if HAVE_LIBCRYPTSETUP
        int r;

        /* libcryptsetup added crypt_reencrypt() in 2.2.0, and marked it obsolete in 2.4.0, replacing it with
         * crypt_reencrypt_run(), which takes one extra argument but is otherwise identical. The old call is
         * still available though, and given we want to support 2.2.0 for a while longer, we'll stick to the
         * old symbol. However, the old symbols now has a GCC deprecation decorator, hence let's turn off
         * warnings about this for now. */

        DISABLE_WARNING_DEPRECATED_DECLARATIONS;

        r = dlopen_many_sym_or_warn(
                        &cryptsetup_dl, "libcryptsetup.so.12", LOG_DEBUG,
                        DLSYM_ARG(crypt_activate_by_passphrase),
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        DLSYM_ARG(crypt_activate_by_signed_key),
#endif
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
                        DLSYM_ARG(crypt_resume_by_passphrase),
                        DLSYM_ARG(crypt_set_data_device),
                        DLSYM_ARG(crypt_set_debug_level),
                        DLSYM_ARG(crypt_set_log_callback),
#if HAVE_CRYPT_SET_METADATA_SIZE
                        DLSYM_ARG(crypt_set_metadata_size),
#endif
                        DLSYM_ARG(crypt_set_pbkdf_type),
                        DLSYM_ARG(crypt_suspend),
                        DLSYM_ARG(crypt_token_json_get),
                        DLSYM_ARG(crypt_token_json_set),
#if HAVE_CRYPT_TOKEN_MAX
                        DLSYM_ARG(crypt_token_max),
#endif
                        DLSYM_ARG(crypt_token_status),
                        DLSYM_ARG(crypt_volume_key_get),
#if HAVE_CRYPT_REENCRYPT_INIT_BY_PASSPHRASE
                        DLSYM_ARG(crypt_reencrypt_init_by_passphrase),
#endif
#if HAVE_CRYPT_REENCRYPT
                        DLSYM_ARG(crypt_reencrypt),
#endif
                        DLSYM_ARG(crypt_metadata_locking),
#if HAVE_CRYPT_SET_DATA_OFFSET
                        DLSYM_ARG(crypt_set_data_offset),
#endif
                        DLSYM_ARG(crypt_header_restore),
                        DLSYM_ARG(crypt_volume_key_keyring));
        if (r <= 0)
                return r;

        REENABLE_WARNING;

        /* Redirect the default logging calls of libcryptsetup to our own logging infra. (Note that
         * libcryptsetup also maintains per-"struct crypt_device" log functions, which we'll also set
         * whenever allocating a "struct crypt_device" context. Why set both? To be defensive: maybe some
         * other code loaded into this process also changes the global log functions of libcryptsetup, who
         * knows? And if so, we still want our own objects to log via our own infra, at the very least.) */
        cryptsetup_enable_logging(NULL);
        return 1;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "cryptsetup support is not compiled in.");
#endif
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
