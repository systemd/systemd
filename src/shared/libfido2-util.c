/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libfido2-util.h"

#if HAVE_LIBFIDO2
#include "alloc-util.h"
#include "ask-password-api.h"
#include "dlfcn-util.h"
#include "format-table.h"
#include "locale-util.h"
#include "log.h"
#include "memory-util.h"
#include "random-util.h"
#include "strv.h"

static void *libfido2_dl = NULL;

int (*sym_fido_assert_allow_cred)(fido_assert_t *, const unsigned char *, size_t) = NULL;
void (*sym_fido_assert_free)(fido_assert_t **) = NULL;
size_t (*sym_fido_assert_hmac_secret_len)(const fido_assert_t *, size_t) = NULL;
const unsigned char* (*sym_fido_assert_hmac_secret_ptr)(const fido_assert_t *, size_t) = NULL;
fido_assert_t* (*sym_fido_assert_new)(void) = NULL;
int (*sym_fido_assert_set_clientdata_hash)(fido_assert_t *, const unsigned char *, size_t) = NULL;
int (*sym_fido_assert_set_extensions)(fido_assert_t *, int) = NULL;
int (*sym_fido_assert_set_hmac_salt)(fido_assert_t *, const unsigned char *, size_t) = NULL;
int (*sym_fido_assert_set_rp)(fido_assert_t *, const char *) = NULL;
int (*sym_fido_assert_set_up)(fido_assert_t *, fido_opt_t) = NULL;
size_t (*sym_fido_cbor_info_extensions_len)(const fido_cbor_info_t *) = NULL;
char **(*sym_fido_cbor_info_extensions_ptr)(const fido_cbor_info_t *) = NULL;
void (*sym_fido_cbor_info_free)(fido_cbor_info_t **) = NULL;
fido_cbor_info_t* (*sym_fido_cbor_info_new)(void) = NULL;
size_t (*sym_fido_cbor_info_options_len)(const fido_cbor_info_t *) = NULL;
char** (*sym_fido_cbor_info_options_name_ptr)(const fido_cbor_info_t *) = NULL;
const bool* (*sym_fido_cbor_info_options_value_ptr)(const fido_cbor_info_t *) = NULL;
void (*sym_fido_cred_free)(fido_cred_t **) = NULL;
size_t (*sym_fido_cred_id_len)(const fido_cred_t *) = NULL;
const unsigned char* (*sym_fido_cred_id_ptr)(const fido_cred_t *) = NULL;
fido_cred_t* (*sym_fido_cred_new)(void) = NULL;
int (*sym_fido_cred_set_clientdata_hash)(fido_cred_t *, const unsigned char *, size_t) = NULL;
int (*sym_fido_cred_set_extensions)(fido_cred_t *, int) = NULL;
int (*sym_fido_cred_set_rk)(fido_cred_t *, fido_opt_t) = NULL;
int (*sym_fido_cred_set_rp)(fido_cred_t *, const char *, const char *) = NULL;
int (*sym_fido_cred_set_type)(fido_cred_t *, int) = NULL;
int (*sym_fido_cred_set_user)(fido_cred_t *, const unsigned char *, size_t, const char *, const char *, const char *) = NULL;
int (*sym_fido_cred_set_uv)(fido_cred_t *, fido_opt_t) = NULL;
void (*sym_fido_dev_free)(fido_dev_t **) = NULL;
int (*sym_fido_dev_get_assert)(fido_dev_t *, fido_assert_t *, const char *) = NULL;
int (*sym_fido_dev_get_cbor_info)(fido_dev_t *, fido_cbor_info_t *) = NULL;
void (*sym_fido_dev_info_free)(fido_dev_info_t **, size_t) = NULL;
int (*sym_fido_dev_info_manifest)(fido_dev_info_t *, size_t, size_t *) = NULL;
const char* (*sym_fido_dev_info_manufacturer_string)(const fido_dev_info_t *) = NULL;
const char* (*sym_fido_dev_info_product_string)(const fido_dev_info_t *) = NULL;
fido_dev_info_t* (*sym_fido_dev_info_new)(size_t) = NULL;
const char* (*sym_fido_dev_info_path)(const fido_dev_info_t *) = NULL;
const fido_dev_info_t* (*sym_fido_dev_info_ptr)(const fido_dev_info_t *, size_t) = NULL;
bool (*sym_fido_dev_is_fido2)(const fido_dev_t *) = NULL;
int (*sym_fido_dev_make_cred)(fido_dev_t *, fido_cred_t *, const char *) = NULL;
fido_dev_t* (*sym_fido_dev_new)(void) = NULL;
int (*sym_fido_dev_open)(fido_dev_t *, const char *) = NULL;
const char* (*sym_fido_strerr)(int) = NULL;

int dlopen_libfido2(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (libfido2_dl)
                return 0; /* Already loaded */

        dl = dlopen("libfido2.so.1", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libfido2 support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(fido_assert_allow_cred),
                        DLSYM_ARG(fido_assert_free),
                        DLSYM_ARG(fido_assert_hmac_secret_len),
                        DLSYM_ARG(fido_assert_hmac_secret_ptr),
                        DLSYM_ARG(fido_assert_new),
                        DLSYM_ARG(fido_assert_set_clientdata_hash),
                        DLSYM_ARG(fido_assert_set_extensions),
                        DLSYM_ARG(fido_assert_set_hmac_salt),
                        DLSYM_ARG(fido_assert_set_rp),
                        DLSYM_ARG(fido_assert_set_up),
                        DLSYM_ARG(fido_cbor_info_extensions_len),
                        DLSYM_ARG(fido_cbor_info_extensions_ptr),
                        DLSYM_ARG(fido_cbor_info_free),
                        DLSYM_ARG(fido_cbor_info_new),
                        DLSYM_ARG(fido_cbor_info_options_len),
                        DLSYM_ARG(fido_cbor_info_options_name_ptr),
                        DLSYM_ARG(fido_cbor_info_options_value_ptr),
                        DLSYM_ARG(fido_cred_free),
                        DLSYM_ARG(fido_cred_id_len),
                        DLSYM_ARG(fido_cred_id_ptr),
                        DLSYM_ARG(fido_cred_new),
                        DLSYM_ARG(fido_cred_set_clientdata_hash),
                        DLSYM_ARG(fido_cred_set_extensions),
                        DLSYM_ARG(fido_cred_set_rk),
                        DLSYM_ARG(fido_cred_set_rp),
                        DLSYM_ARG(fido_cred_set_type),
                        DLSYM_ARG(fido_cred_set_user),
                        DLSYM_ARG(fido_cred_set_uv),
                        DLSYM_ARG(fido_dev_free),
                        DLSYM_ARG(fido_dev_get_assert),
                        DLSYM_ARG(fido_dev_get_cbor_info),
                        DLSYM_ARG(fido_dev_info_free),
                        DLSYM_ARG(fido_dev_info_manifest),
                        DLSYM_ARG(fido_dev_info_manufacturer_string),
                        DLSYM_ARG(fido_dev_info_new),
                        DLSYM_ARG(fido_dev_info_path),
                        DLSYM_ARG(fido_dev_info_product_string),
                        DLSYM_ARG(fido_dev_info_ptr),
                        DLSYM_ARG(fido_dev_is_fido2),
                        DLSYM_ARG(fido_dev_make_cred),
                        DLSYM_ARG(fido_dev_new),
                        DLSYM_ARG(fido_dev_open),
                        DLSYM_ARG(fido_strerr),
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        libfido2_dl = TAKE_PTR(dl);
        return 1;
}

static int verify_features(
                fido_dev_t *d,
                const char *path,
                int log_level, /* the log level to use when device is not FIDO2 with hmac-secret */
                bool *ret_has_rk,
                bool *ret_has_client_pin,
                bool *ret_has_up,
                bool *ret_has_uv) {

        _cleanup_(fido_cbor_info_free_wrapper) fido_cbor_info_t *di = NULL;
        bool found_extension = false;
        char **e, **o;
        const bool *b;
        bool has_rk = false, has_client_pin = false, has_up = true, has_uv = false; /* Defaults are per table in 5.4 in FIDO2 spec */
        size_t n;
        int r;

        assert(d);
        assert(path);

        if (!sym_fido_dev_is_fido2(d))
                return log_full_errno(log_level,
                                      SYNTHETIC_ERRNO(ENODEV),
                                       "Specified device %s is not a FIDO2 device.", path);

        di = sym_fido_cbor_info_new();
        if (!di)
                return log_oom();

        r = sym_fido_dev_get_cbor_info(d, di);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to get CBOR device info for %s: %s", path, sym_fido_strerr(r));

        e = sym_fido_cbor_info_extensions_ptr(di);
        n = sym_fido_cbor_info_extensions_len(di);
        for (size_t i = 0; i < n; i++) {
                log_debug("FIDO2 device implements extension: %s", e[i]);
                if (streq(e[i], "hmac-secret"))
                        found_extension = true;
        }

        o = sym_fido_cbor_info_options_name_ptr(di);
        b = sym_fido_cbor_info_options_value_ptr(di);
        n = sym_fido_cbor_info_options_len(di);
        for (size_t i = 0; i < n; i++) {
                log_debug("FIDO2 device implements option %s: %s", o[i], yes_no(b[i]));
                if (streq(o[i], "rk"))
                        has_rk = b[i];
                if (streq(o[i], "clientPin"))
                        has_client_pin = b[i];
                if (streq(o[i], "up"))
                        has_up = b[i];
                if (streq(o[i], "uv"))
                        has_uv = b[i];
        }

        if (!found_extension)
                return log_full_errno(log_level,
                                      SYNTHETIC_ERRNO(ENODEV),
                                       "Specified device %s is a FIDO2 device, but does not support the required HMAC-SECRET extension.", path);

        log_debug("Has rk ('Resident Key') support: %s\n"
                  "Has clientPin support: %s\n"
                  "Has up ('User Presence') support: %s\n"
                  "Has uv ('User Verification') support: %s\n",
                  yes_no(has_rk),
                  yes_no(has_client_pin),
                  yes_no(has_up),
                  yes_no(has_uv));

        if (ret_has_rk)
                *ret_has_rk = has_rk;
        if (ret_has_client_pin)
                *ret_has_client_pin = has_client_pin;
        if (ret_has_up)
                *ret_has_up = has_up;
        if (ret_has_uv)
                *ret_has_uv = has_uv;

        return 0;
}

static int fido2_use_hmac_hash_specific_token(
                const char *path,
                const char *rp_id,
                const void *salt,
                size_t salt_size,
                const void *cid,
                size_t cid_size,
                char **pins,
                bool up, /* user presence permitted */
                void **ret_hmac,
                size_t *ret_hmac_size) {

        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        _cleanup_(erase_and_freep) void *hmac_copy = NULL;
        bool has_up, has_client_pin;
        size_t hmac_size;
        const void *hmac;
        int r;

        assert(path);
        assert(rp_id);
        assert(salt);
        assert(cid);
        assert(ret_hmac);
        assert(ret_hmac_size);

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, path);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", path, sym_fido_strerr(r));

        r = verify_features(d, path, LOG_ERR, NULL, &has_client_pin, &has_up, NULL);
        if (r < 0)
                return r;

        a = sym_fido_assert_new();
        if (!a)
                return log_oom();

        r = sym_fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to enable HMAC-SECRET extension on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_hmac_salt(a, salt, salt_size);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set salt on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_rp(a, rp_id);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion ID: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_clientdata_hash(a, (const unsigned char[32]) {}, 32);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion client data hash: %s", sym_fido_strerr(r));

        r = sym_fido_assert_allow_cred(a, cid, cid_size);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to add FIDO2 assertion credential ID: %s", sym_fido_strerr(r));

        if (has_up) {
                r = sym_fido_assert_set_up(a, FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to set FIDO2 assertion user presence: %s", sym_fido_strerr(r));
        }

        log_info("Asking FIDO2 token for authentication.");

        r = sym_fido_dev_get_assert(d, a, NULL); /* try without pin and without up first */
        if (r == FIDO_ERR_UP_REQUIRED && up) {

                if (!has_up)
                        log_warning("Weird, device asked for User Presence check, but does not advertise it as feature. Ignoring.");

                r = sym_fido_assert_set_up(a, FIDO_OPT_TRUE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion user presence: %s", sym_fido_strerr(r));

                log_info("Security token requires user presence.");

                r = sym_fido_dev_get_assert(d, a, NULL); /* try without pin but with up now */
        }
        if (r == FIDO_ERR_PIN_REQUIRED) {
                char **i;

                if (!has_client_pin)
                        log_warning("Weird, device asked for client PIN, but does not advertise it as feature. Ignoring.");

                /* OK, we needed a pin, try with all pins in turn */
                STRV_FOREACH(i, pins) {
                        r = sym_fido_dev_get_assert(d, a, *i);
                        if (r != FIDO_ERR_PIN_INVALID)
                                break;
                }
        }

        switch (r) {
        case FIDO_OK:
                break;
        case FIDO_ERR_NO_CREDENTIALS:
                return log_error_errno(SYNTHETIC_ERRNO(EBADSLT),
                                       "Wrong security token; needed credentials not present on token.");
        case FIDO_ERR_PIN_REQUIRED:
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO),
                                       "Security token requires PIN.");
        case FIDO_ERR_PIN_AUTH_BLOCKED:
                return log_error_errno(SYNTHETIC_ERRNO(EOWNERDEAD),
                                       "PIN of security token is blocked, please remove/reinsert token.");
        case FIDO_ERR_PIN_INVALID:
                return log_error_errno(SYNTHETIC_ERRNO(ENOLCK),
                                       "PIN of security token incorrect.");
        case FIDO_ERR_UP_REQUIRED:
                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE),
                                       "User presence required.");
        case FIDO_ERR_ACTION_TIMEOUT:
                return log_error_errno(SYNTHETIC_ERRNO(ENOSTR),
                                       "Token action timeout. (User didn't interact with token quickly enough.)");
        default:
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to ask token for assertion: %s", sym_fido_strerr(r));
        }

        hmac = sym_fido_assert_hmac_secret_ptr(a, 0);
        if (!hmac)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve HMAC secret.");

        hmac_size = sym_fido_assert_hmac_secret_len(a, 0);

        hmac_copy = memdup(hmac, hmac_size);
        if (!hmac_copy)
                return log_oom();

        *ret_hmac = TAKE_PTR(hmac_copy);
        *ret_hmac_size = hmac_size;
        return 0;
}

int fido2_use_hmac_hash(
                const char *device,
                const char *rp_id,
                const void *salt,
                size_t salt_size,
                const void *cid,
                size_t cid_size,
                char **pins,
                bool up, /* user presence permitted */
                void **ret_hmac,
                size_t *ret_hmac_size) {

        size_t allocated = 64, found = 0;
        fido_dev_info_t *di = NULL;
        int r;

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 support is not installed.");

        if (device)
                return fido2_use_hmac_hash_specific_token(device, rp_id, salt, salt_size, cid, cid_size, pins, up, ret_hmac, ret_hmac_size);

        di = sym_fido_dev_info_new(allocated);
        if (!di)
                return log_oom();

        r = sym_fido_dev_info_manifest(di, allocated, &found);
        if (r == FIDO_ERR_INTERNAL) {
                /* The library returns FIDO_ERR_INTERNAL when no devices are found. I wish it wouldn't. */
                r = log_debug_errno(SYNTHETIC_ERRNO(EAGAIN), "Got FIDO_ERR_INTERNAL, assuming no devices.");
                goto finish;
        }
        if (r != FIDO_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to enumerate FIDO2 devices: %s", sym_fido_strerr(r));
                goto finish;
        }

        for (size_t i = 0; i < found; i++) {
                const fido_dev_info_t *entry;
                const char *path;

                entry = sym_fido_dev_info_ptr(di, i);
                if (!entry) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                            "Failed to get device information for FIDO device %zu.", i);
                        goto finish;
                }

                path = sym_fido_dev_info_path(entry);
                if (!path) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                            "Failed to query FIDO device path.");
                        goto finish;
                }

                r = fido2_use_hmac_hash_specific_token(path, rp_id, salt, salt_size, cid, cid_size, pins, up, ret_hmac, ret_hmac_size);
                if (!IN_SET(r,
                            -EBADSLT, /* device doesn't understand our credential hash */
                            -ENODEV   /* device is not a FIDO2 device with HMAC-SECRET */))
                        goto finish;
        }

        r = -EAGAIN;

finish:
        sym_fido_dev_info_free(&di, allocated);
        return r;
}

#define FIDO2_SALT_SIZE 32

int fido2_generate_hmac_hash(
                const char *device,
                const char *rp_id,
                const char *rp_name,
                const void *user_id, size_t user_id_len,
                const char *user_name,
                const char *user_display_name,
                const char *user_icon,
                const char *askpw_icon_name,
                void **ret_cid, size_t *ret_cid_size,
                void **ret_salt, size_t *ret_salt_size,
                void **ret_secret, size_t *ret_secret_size,
                char **ret_usedpin) {

        _cleanup_(erase_and_freep) void *salt = NULL, *secret_copy = NULL;
        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        _cleanup_(fido_cred_free_wrapper) fido_cred_t *c = NULL;
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        _cleanup_(erase_and_freep) char *used_pin = NULL;
        bool has_rk, has_client_pin, has_up, has_uv;
        _cleanup_free_ char *cid_copy = NULL;
        size_t cid_size, secret_size;
        const void *cid, *secret;
        int r;

        assert(device);
        assert(ret_cid);
        assert(ret_cid_size);
        assert(ret_salt);
        assert(ret_salt_size);
        assert(ret_secret);
        assert(ret_secret_size);

        /* Construction is like this: we generate a salt of 32 bytes. We then ask the FIDO2 device to
         * HMAC-SHA256 it for us with its internal key. The result is the key used by LUKS and account
         * authentication. LUKS and UNIX password auth all do their own salting before hashing, so that FIDO2
         * device never sees the volume key.
         *
         * S = HMAC-SHA256(I, D)
         *
         * with: S → LUKS/account authentication key                                         (never stored)
         *       I → internal key on FIDO2 device                              (stored in the FIDO2 device)
         *       D → salt we generate here               (stored in the privileged part of the JSON record)
         *
         */

        assert(device);

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 token support is not installed.");

        salt = malloc(FIDO2_SALT_SIZE);
        if (!salt)
                return log_oom();

        r = genuine_random_bytes(salt, FIDO2_SALT_SIZE, RANDOM_BLOCK);
        if (r < 0)
                return log_error_errno(r, "Failed to generate salt: %m");

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, device);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", device, sym_fido_strerr(r));

        r = verify_features(d, device, LOG_ERR, &has_rk, &has_client_pin, &has_up, &has_uv);
        if (r < 0)
                return r;

        c = sym_fido_cred_new();
        if (!c)
                return log_oom();

        r = sym_fido_cred_set_extensions(c, FIDO_EXT_HMAC_SECRET);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to enable HMAC-SECRET extension on FIDO2 credential: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_rp(c, rp_id, rp_name);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 credential relying party ID/name: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_type(c, COSE_ES256);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 credential type to ES256: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_user(
                        c,
                        user_id, user_id_len,
                        user_name,
                        user_display_name,
                        user_icon);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 credential user data: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_clientdata_hash(c, (const unsigned char[32]) {}, 32);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 client data hash: %s", sym_fido_strerr(r));

        if (has_rk) {
                r = sym_fido_cred_set_rk(c, FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to turn off FIDO2 resident key option of credential: %s", sym_fido_strerr(r));
        }

        if (has_uv) {
                r = sym_fido_cred_set_uv(c, FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to turn off FIDO2 user verification option of credential: %s", sym_fido_strerr(r));
        }

        log_info("Initializing FIDO2 credential on security token.");

        log_notice("%s%s(Hint: This might require verification of user presence on security token.)",
                   emoji_enabled() ? special_glyph(SPECIAL_GLYPH_TOUCH) : "",
                   emoji_enabled() ? " " : "");

        r = sym_fido_dev_make_cred(d, c, NULL);
        if (r == FIDO_ERR_PIN_REQUIRED) {
                for (;;) {
                        _cleanup_(strv_free_erasep) char **pin = NULL;
                        char **i;

                        if (!has_client_pin)
                                log_warning("Weird, device asked for client PIN, but does not advertise it as feature. Ignoring.");

                        r = ask_password_auto("Please enter security token PIN:", askpw_icon_name, NULL, "fido2-pin", USEC_INFINITY, 0, &pin);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire user PIN: %m");

                        r = FIDO_ERR_PIN_INVALID;
                        STRV_FOREACH(i, pin) {
                                if (isempty(*i)) {
                                        log_info("PIN may not be empty.");
                                        continue;
                                }

                                r = sym_fido_dev_make_cred(d, c, *i);
                                if (r == FIDO_OK) {
                                        used_pin = strdup(*i);
                                        if (!used_pin)
                                                return log_oom();
                                        break;
                                }
                                if (r != FIDO_ERR_PIN_INVALID)
                                        break;
                        }

                        if (r != FIDO_ERR_PIN_INVALID)
                                break;

                        log_notice("PIN incorrect, please try again.");
                }
        }
        if (r == FIDO_ERR_PIN_AUTH_BLOCKED)
                return log_notice_errno(SYNTHETIC_ERRNO(EPERM),
                                        "Token PIN is currently blocked, please remove and reinsert token.");
        if (r == FIDO_ERR_ACTION_TIMEOUT)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSTR),
                                       "Token action timeout. (User didn't interact with token quickly enough.)");
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to generate FIDO2 credential: %s", sym_fido_strerr(r));

        cid = sym_fido_cred_id_ptr(c);
        if (!cid)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get FIDO2 credential ID.");

        cid_size = sym_fido_cred_id_len(c);

        a = sym_fido_assert_new();
        if (!a)
                return log_oom();

        r = sym_fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to enable HMAC-SECRET extension on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_hmac_salt(a, salt, FIDO2_SALT_SIZE);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set salt on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_rp(a, rp_id);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion ID: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_clientdata_hash(a, (const unsigned char[32]) {}, 32);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion client data hash: %s", sym_fido_strerr(r));

        r = sym_fido_assert_allow_cred(a, cid, cid_size);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to add FIDO2 assertion credential ID: %s", sym_fido_strerr(r));

        if (has_up) {
                r = sym_fido_assert_set_up(a, FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to turn off FIDO2 assertion user presence: %s", sym_fido_strerr(r));
        }

        log_info("Generating secret key on FIDO2 security token.");

        r = sym_fido_dev_get_assert(d, a, used_pin);
        if (r == FIDO_ERR_UP_REQUIRED) {

                if (!has_up)
                        log_warning("Weird, device asked for User Presence check, but does not advertise it as feature. Ignoring.");

                r = sym_fido_assert_set_up(a, FIDO_OPT_TRUE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to turn on FIDO2 assertion user presence: %s", sym_fido_strerr(r));

                log_notice("%s%sIn order to allow secret key generation, please verify presence on security token.",
                           emoji_enabled() ? special_glyph(SPECIAL_GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

                r = sym_fido_dev_get_assert(d, a, used_pin);
        }
        if (r == FIDO_ERR_ACTION_TIMEOUT)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSTR),
                                       "Token action timeout. (User didn't interact with token quickly enough.)");
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to ask token for assertion: %s", sym_fido_strerr(r));

        secret = sym_fido_assert_hmac_secret_ptr(a, 0);
        if (!secret)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve HMAC secret.");

        secret_size = sym_fido_assert_hmac_secret_len(a, 0);

        secret_copy = memdup(secret, secret_size);
        if (!secret_copy)
                return log_oom();

        cid_copy = memdup(cid, cid_size);
        if (!cid_copy)
                return log_oom();

        *ret_cid = TAKE_PTR(cid_copy);
        *ret_cid_size = cid_size;
        *ret_salt = TAKE_PTR(salt);
        *ret_salt_size = FIDO2_SALT_SIZE;
        *ret_secret = TAKE_PTR(secret_copy);
        *ret_secret_size = secret_size;

        if (ret_usedpin)
                *ret_usedpin = TAKE_PTR(used_pin);

        return 0;
}
#endif

#if HAVE_LIBFIDO2
static int check_device_is_fido2_with_hmac_secret(const char *path) {
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        int r;

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, path);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", path, sym_fido_strerr(r));

        r = verify_features(d, path, LOG_DEBUG, NULL, NULL, NULL, NULL);
        if (r == -ENODEV) /* Not a FIDO2 device, or not implementing 'hmac-secret' */
                return false;
        if (r < 0)
                return r;

        return true;
}
#endif

int fido2_list_devices(void) {
#if HAVE_LIBFIDO2
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t allocated = 64, found = 0;
        fido_dev_info_t *di = NULL;
        int r;

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 token support is not installed.");

        di = sym_fido_dev_info_new(allocated);
        if (!di)
                return log_oom();

        r = sym_fido_dev_info_manifest(di, allocated, &found);
        if (r == FIDO_ERR_INTERNAL || (r == FIDO_OK && found == 0)) {
                /* The library returns FIDO_ERR_INTERNAL when no devices are found. I wish it wouldn't. */
                log_info("No FIDO2 devices found.");
                r = 0;
                goto finish;
        }
        if (r != FIDO_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to enumerate FIDO2 devices: %s", sym_fido_strerr(r));
                goto finish;
        }

        t = table_new("path", "manufacturer", "product");
        if (!t) {
                r = log_oom();
                goto finish;
        }

        for (size_t i = 0; i < found; i++) {
                const fido_dev_info_t *entry;

                entry = sym_fido_dev_info_ptr(di, i);
                if (!entry) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                            "Failed to get device information for FIDO device %zu.", i);
                        goto finish;
                }

                r = check_device_is_fido2_with_hmac_secret(sym_fido_dev_info_path(entry));
                if (r < 0)
                        goto finish;
                if (!r)
                        continue;

                r = table_add_many(
                                t,
                                TABLE_PATH, sym_fido_dev_info_path(entry),
                                TABLE_STRING, sym_fido_dev_info_manufacturer_string(entry),
                                TABLE_STRING, sym_fido_dev_info_product_string(entry));
                if (r < 0) {
                        table_log_add_error(r);
                        goto finish;
                }
        }

        r = table_print(t, stdout);
        if (r < 0) {
                log_error_errno(r, "Failed to show device table: %m");
                goto finish;
        }

        r = 0;

finish:
        sym_fido_dev_info_free(&di, allocated);
        return r;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 tokens not supported on this build.");
#endif
}

int fido2_find_device_auto(char **ret) {
#if HAVE_LIBFIDO2
        _cleanup_free_ char *copy = NULL;
        size_t di_size = 64, found = 0;
        const fido_dev_info_t *entry;
        fido_dev_info_t *di = NULL;
        const char *path;
        int r;

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 token support is not installed.");

        di = sym_fido_dev_info_new(di_size);
        if (!di)
                return log_oom();

        r = sym_fido_dev_info_manifest(di, di_size, &found);
        if (r == FIDO_ERR_INTERNAL || (r == FIDO_OK && found == 0)) {
                /* The library returns FIDO_ERR_INTERNAL when no devices are found. I wish it wouldn't. */
                r = log_error_errno(SYNTHETIC_ERRNO(ENODEV), "No FIDO devices found.");
                goto finish;
        }
        if (r != FIDO_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to enumerate FIDO devices: %s", sym_fido_strerr(r));
                goto finish;
        }
        if (found > 1) {
                r = log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ), "More than one FIDO device found.");
                goto finish;
        }

        entry = sym_fido_dev_info_ptr(di, 0);
        if (!entry) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                    "Failed to get device information for FIDO device 0.");
                goto finish;
        }

        r = check_device_is_fido2_with_hmac_secret(sym_fido_dev_info_path(entry));
        if (r < 0)
                goto finish;
        if (!r) {
                r = log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "FIDO device discovered does not implement FIDO2 with 'hmac-secret' extension.");
                goto finish;
        }

        path = sym_fido_dev_info_path(entry);
        if (!path) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                    "Failed to query FIDO device path.");
                goto finish;
        }

        copy = strdup(path);
        if (!copy) {
                r = log_oom();
                goto finish;
        }

        *ret = TAKE_PTR(copy);
        r = 0;

finish:
        sym_fido_dev_info_free(&di, di_size);
        return r;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 tokens not supported on this build.");
#endif
}
