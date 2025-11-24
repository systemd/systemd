/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libfido2-util.h"
#include "log.h"

#if HAVE_LIBFIDO2
#include "alloc-util.h"
#include "ansi-color.h"
#include "ask-password-api.h"
#include "dlfcn-util.h"
#include "format-table.h"
#include "glyph-util.h"
#include "iovec-util.h"
#include "plymouth-util.h"
#include "string-util.h"
#include "strv.h"
#include "unistd.h"

static void *libfido2_dl = NULL;

DLSYM_PROTOTYPE(fido_assert_allow_cred) = NULL;
DLSYM_PROTOTYPE(fido_assert_free) = NULL;
DLSYM_PROTOTYPE(fido_assert_hmac_secret_len) = NULL;
DLSYM_PROTOTYPE(fido_assert_hmac_secret_ptr) = NULL;
DLSYM_PROTOTYPE(fido_assert_new) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_clientdata_hash) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_extensions) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_hmac_salt) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_rp) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_up) = NULL;
DLSYM_PROTOTYPE(fido_assert_set_uv) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_extensions_len) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_extensions_ptr) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_free) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_new) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_options_len) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_options_name_ptr) = NULL;
DLSYM_PROTOTYPE(fido_cbor_info_options_value_ptr) = NULL;
DLSYM_PROTOTYPE(fido_cred_free) = NULL;
DLSYM_PROTOTYPE(fido_cred_id_len) = NULL;
DLSYM_PROTOTYPE(fido_cred_id_ptr) = NULL;
DLSYM_PROTOTYPE(fido_cred_new) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_clientdata_hash) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_extensions) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_prot) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_rk) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_rp) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_type) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_user) = NULL;
DLSYM_PROTOTYPE(fido_cred_set_uv) = NULL;
DLSYM_PROTOTYPE(fido_dev_close) = NULL;
DLSYM_PROTOTYPE(fido_dev_free) = NULL;
DLSYM_PROTOTYPE(fido_dev_get_assert) = NULL;
DLSYM_PROTOTYPE(fido_dev_get_cbor_info) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_free) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_manifest) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_manufacturer_string) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_new) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_path) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_product_string) = NULL;
DLSYM_PROTOTYPE(fido_dev_info_ptr) = NULL;
DLSYM_PROTOTYPE(fido_dev_is_fido2) = NULL;
DLSYM_PROTOTYPE(fido_dev_make_cred) = NULL;
DLSYM_PROTOTYPE(fido_dev_new) = NULL;
DLSYM_PROTOTYPE(fido_dev_open) = NULL;
DLSYM_PROTOTYPE(fido_init) = NULL;
DLSYM_PROTOTYPE(fido_set_log_handler) = NULL;
DLSYM_PROTOTYPE(fido_strerr) = NULL;

static void fido_log_propagate_handler(const char *s) {
        log_debug("libfido2: %s", strempty(s));
}

int dlopen_libfido2(void) {
        int r;

        ELF_NOTE_DLOPEN("fido2",
                        "Support fido2 for encryption and authentication",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libfido2.so.1");

        r = dlopen_many_sym_or_warn(
                        &libfido2_dl, "libfido2.so.1", LOG_DEBUG,
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
                        DLSYM_ARG(fido_assert_set_uv),
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
                        DLSYM_ARG(fido_cred_set_prot),
                        DLSYM_ARG(fido_cred_set_rk),
                        DLSYM_ARG(fido_cred_set_rp),
                        DLSYM_ARG(fido_cred_set_type),
                        DLSYM_ARG(fido_cred_set_user),
                        DLSYM_ARG(fido_cred_set_uv),
                        DLSYM_ARG(fido_dev_close),
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
                        DLSYM_ARG(fido_init),
                        DLSYM_ARG(fido_set_log_handler),
                        DLSYM_ARG(fido_strerr));
        if (r < 0)
                return r;

        sym_fido_init(FIDO_DEBUG);
        sym_fido_set_log_handler(fido_log_propagate_handler);

        return 0;
}

static int verify_features(
                fido_dev_t *d,
                const char *path,
                int log_level, /* the log level to use when device is not FIDO2 with hmac-secret */
                bool *ret_has_rk,
                bool *ret_has_client_pin,
                bool *ret_has_up,
                bool *ret_has_uv,
                bool *ret_has_always_uv) {

        _cleanup_(fido_cbor_info_free_wrapper) fido_cbor_info_t *di = NULL;
        bool found_extension = false;
        char **e, **o;
        const bool *b;
        bool has_rk = false, has_client_pin = false, has_up = true, has_uv = false, has_always_uv = false; /* Defaults are per table in 5.4 in FIDO2 spec */
        size_t n;
        int r;

        assert(d);
        assert(path);

        if (!sym_fido_dev_is_fido2(d))
                return log_full_errno(log_level, SYNTHETIC_ERRNO(ENODEV),
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
                if (streq(o[i], "alwaysUv"))
                        has_always_uv = b[i];
        }

        if (!found_extension)
                return log_full_errno(log_level,
                                      SYNTHETIC_ERRNO(ENODEV),
                                       "Specified device %s is a FIDO2 device, but does not support the required HMAC-SECRET extension.", path);

        log_debug("Has rk ('Resident Key') support: %s\n"
                  "Has clientPin support: %s\n"
                  "Has up ('User Presence') support: %s\n"
                  "Has uv ('User Verification') support: %s\n"
                  "Has alwaysUv ('User Verification' required): %s\n",
                  yes_no(has_rk),
                  yes_no(has_client_pin),
                  yes_no(has_up),
                  yes_no(has_uv),
                  yes_no(has_always_uv));

        if (ret_has_rk)
                *ret_has_rk = has_rk;
        if (ret_has_client_pin)
                *ret_has_client_pin = has_client_pin;
        if (ret_has_up)
                *ret_has_up = has_up;
        if (ret_has_uv)
                *ret_has_uv = has_uv;
        if (ret_has_always_uv)
                *ret_has_always_uv = has_always_uv;

        return 0;
}

static int fido2_assert_set_basic_properties(
                fido_assert_t *a,
                const char *rp_id,
                const void *cid,
                size_t cid_size) {
        int r;

        assert(a);
        assert(rp_id);
        assert(cid);
        assert(cid_size > 0);

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

        return 0;
}

static int fido2_common_assert_error_handle(int r) {
        switch (r) {
        case FIDO_OK:
                return 0;
        case FIDO_ERR_NO_CREDENTIALS:
                return log_error_errno(SYNTHETIC_ERRNO(EBADSLT),
                                       "Wrong security token; needed credentials not present on token.");
        case FIDO_ERR_PIN_REQUIRED:
                return log_error_errno(SYNTHETIC_ERRNO(ENOANO),
                                       "Security token requires PIN.");
        case FIDO_ERR_PIN_AUTH_BLOCKED:
                return log_error_errno(SYNTHETIC_ERRNO(EOWNERDEAD),
                                       "PIN of security token is blocked, please remove/reinsert token.");
#ifdef FIDO_ERR_UV_BLOCKED
        case FIDO_ERR_UV_BLOCKED:
                return log_error_errno(SYNTHETIC_ERRNO(EOWNERDEAD),
                                       "Verification of security token is blocked, please remove/reinsert token.");
#endif
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
}

static int fido2_is_cred_in_specific_token(
                const char *path,
                const char *rp_id,
                const void *cid,
                size_t cid_size,
                Fido2EnrollFlags flags) {

        assert(path);
        assert(rp_id);
        assert(cid);
        assert(cid_size);

        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        bool has_up = false, has_uv = false;
        int r;

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, path);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", path, sym_fido_strerr(r));

        r = verify_features(d, path, LOG_ERR, /* ret_has_rk= */ NULL, /* ret_has_client_pin= */ NULL, &has_up, &has_uv, /* ret_has_always_uv= */ NULL);
        if (r == -ENODEV) { /* Not a FIDO2 device or lacking HMAC-SECRET extension */
                log_debug_errno(r, "%s is not a FIDO2 device, or it lacks the hmac-secret extension", path);
                return false;
        }
        if (r < 0)
                return r;

        a = sym_fido_assert_new();
        if (!a)
                return log_oom();

        r = fido2_assert_set_basic_properties(a, rp_id, cid, cid_size);
        if (r < 0)
                return r;

        /* FIDO2 devices may not support pre-flight requests with UV, at least not
         * without user interaction [1]. As a result, let's just return true
         * here and go ahead with trying the unlock directly.
         * Reference:
         * 1: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
         *    See section 7.4 */
        if (has_uv && FLAGS_SET(flags, FIDO2ENROLL_UV)) {
                log_debug("Pre-flight requests with UV are unsupported, device: %s", path);
                return true;
        }

        /* According to CTAP 2.1 specification, to do pre-flight we need to set up option to false
         * with optionally pinUvAuthParam in assertion[1]. But for authenticator that doesn't support
         * user presence, once up option is present, the authenticator may return CTAP2_ERR_UNSUPPORTED_OPTION[2].
         * So we simplely omit the option in that case.
         * Reference:
         * 1: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pre-flight
         * 2: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion (in step 5)
         */
        if (has_up)
                r = sym_fido_assert_set_up(a, FIDO_OPT_FALSE);
        else
                r = sym_fido_assert_set_up(a, FIDO_OPT_OMIT);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set assertion user presence: %s", sym_fido_strerr(r));

        r = sym_fido_dev_get_assert(d, a, NULL);

        switch (r) {
                case FIDO_OK:
                        return true;
                case FIDO_ERR_NO_CREDENTIALS:
                        return false;
                default:
                        return fido2_common_assert_error_handle(r);
        }
}

static void plymouth_start_interaction(const char *text, bool *ret_displayed) {
        assert(ret_displayed);

        if (plymouth_send_msg(text, /* pause_spinner= */ true) < 0)
                return;

        *ret_displayed = true;
}

static void plymouth_end_interaction(bool *displayed) {
        assert(displayed);

        if (!*displayed)
                return;

        /* In theory 'm' should hide a message, but it doesn't work (long standing issue).
         * As a workaround, sending a single NUL byte hides the previous messages. */
        (void) plymouth_send_msg("", /* pause_spinner= */ false);
}

static int fido2_use_hmac_hash_specific_token(
                const char *path,
                const char *rp_id,
                const void *salt,
                size_t salt_size,
                const void *cid,
                size_t cid_size,
                char **pins,
                Fido2EnrollFlags required, /* client pin/user presence required */
                void **ret_hmac,
                size_t *ret_hmac_size) {

        _cleanup_(plymouth_end_interaction) bool plymouth_displayed = false;
        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        _cleanup_(erase_and_freep) void *hmac_copy = NULL;
        bool has_up, has_client_pin, has_uv;
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

        r = verify_features(d, path, LOG_ERR, /* ret_has_rk= */ NULL, &has_client_pin, &has_up, &has_uv, /* ret_has_always_uv= */ NULL);
        if (r < 0)
                return r;

        if (!has_client_pin && FLAGS_SET(required, FIDO2ENROLL_PIN))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON),
                                       "PIN required to unlock, but FIDO2 device %s does not support it.",
                                       path);

        if (!has_up && FLAGS_SET(required, FIDO2ENROLL_UP))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON),
                                       "User presence test required to unlock, but FIDO2 device %s does not support it.",
                                       path);

        if (!has_uv && FLAGS_SET(required, FIDO2ENROLL_UV))
                return log_error_errno(SYNTHETIC_ERRNO(EHWPOISON),
                                       "User verification required to unlock, but FIDO2 device %s does not support it.",
                                       path);

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

        r = fido2_assert_set_basic_properties(a, rp_id, cid, cid_size);
        if (r < 0)
                return r;

        log_info("Asking FIDO2 token for authentication.");

        if (has_up) {
                r = sym_fido_assert_set_up(a, FLAGS_SET(required, FIDO2ENROLL_UP) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to %s FIDO2 user presence test: %s",
                                               enable_disable(FLAGS_SET(required, FIDO2ENROLL_UP)),
                                               sym_fido_strerr(r));

                if (FLAGS_SET(required, FIDO2ENROLL_UP)) {
                        log_notice("%s%sPlease confirm presence on security token to unlock.",
                                   emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                   emoji_enabled() ? " " : "");
                        plymouth_start_interaction("Please confirm presence on security token to unlock.", &plymouth_displayed);
                }
        }

        if (has_uv && !FLAGS_SET(required, FIDO2ENROLL_UV_OMIT)) {
                r = sym_fido_assert_set_uv(a, FLAGS_SET(required, FIDO2ENROLL_UV) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to %s FIDO2 user verification: %s",
                                               enable_disable(FLAGS_SET(required, FIDO2ENROLL_UV)),
                                               sym_fido_strerr(r));

                if (FLAGS_SET(required, FIDO2ENROLL_UV)) {
                        log_notice("%s%sPlease verify user on security token to unlock.",
                                   emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                   emoji_enabled() ? " " : "");
                        plymouth_start_interaction("Please verify user on security token to unlock.", &plymouth_displayed);
                }
        }

        for (;;) {
                bool retry_with_up = false, retry_with_pin = false;

                if (FLAGS_SET(required, FIDO2ENROLL_PIN)) {
                        /* OK, we need a pin, try with all pins in turn */
                        if (strv_isempty(pins))
                                r = FIDO_ERR_PIN_REQUIRED;
                        else
                                STRV_FOREACH(i, pins) {
                                        r = sym_fido_dev_get_assert(d, a, *i);
                                        if (r != FIDO_ERR_PIN_INVALID)
                                                break;
                                }

                } else
                        r = sym_fido_dev_get_assert(d, a, NULL);

                /* In some conditions, where a PIN or UP is required we might accept that. Let's check the
                 * conditions and if so try immediately again. */

                switch (r) {

                case FIDO_ERR_UP_REQUIRED:
                        /* So the token asked for "up". Try to turn it on, for compat with systemd 248 and try again. */

                        if (!has_up)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for user presence test but doesn't advertise 'up' feature.");

                        if (FLAGS_SET(required, FIDO2ENROLL_UP))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for user presence test but was already enabled.");

                        if (FLAGS_SET(required, FIDO2ENROLL_UP_IF_NEEDED)) {
                                log_notice("%s%sPlease confirm presence on security to unlock.",
                                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                           emoji_enabled() ? " " : "");
                                plymouth_start_interaction("Please confirm presence on security token to unlock.", &plymouth_displayed);
                                retry_with_up = true;
                        }

                        break;

                case FIDO_ERR_UNSUPPORTED_OPTION:
                        /* AuthenTrend ATKey.Pro returns this instead of FIDO_ERR_UP_REQUIRED, let's handle
                         * it gracefully (also see below.) */

                        if (has_up && (required & (FIDO2ENROLL_UP|FIDO2ENROLL_UP_IF_NEEDED)) == FIDO2ENROLL_UP_IF_NEEDED) {
                                log_notice("%s%sGot unsupported option error when user presence test is turned off. Trying with user presence test turned on.",
                                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                           emoji_enabled() ? " " : "");
                                retry_with_up = true;
                        }

                        break;

                case FIDO_ERR_PIN_REQUIRED:
                        /* A pin was requested. Maybe supply one, if we are configured to do so on request */

                        if (!has_client_pin)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for PIN but doesn't advertise 'clientPin' feature.");

                        if (FLAGS_SET(required, FIDO2ENROLL_PIN) && !strv_isempty(pins))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for PIN but one was already supplied.");

                        if ((required & (FIDO2ENROLL_PIN|FIDO2ENROLL_PIN_IF_NEEDED)) == FIDO2ENROLL_PIN_IF_NEEDED) {
                                /* If a PIN so far wasn't specified but is requested by the device, and
                                 * FIDO2ENROLL_PIN_IF_NEEDED is set, then provide it */
                                log_debug("Retrying to create credential with PIN.");
                                retry_with_pin = true;
                        }

                        break;

                default:
                        ;
                }

                if (!retry_with_up && !retry_with_pin)
                        break;

                if (retry_with_up) {
                        r = sym_fido_assert_set_up(a, FIDO_OPT_TRUE);
                        if (r != FIDO_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Failed to enable FIDO2 user presence test: %s", sym_fido_strerr(r));

                        required |= FIDO2ENROLL_UP;
                }

                if (retry_with_pin)
                        required |= FIDO2ENROLL_PIN;
        }

        r = fido2_common_assert_error_handle(r);
        if (r < 0)
                return r;

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

/* COSE_ECDH_ES256 is not usable with fido_cred_set_type() thus it's not listed here. */
static const char *fido2_algorithm_to_string(int alg) {
        switch (alg) {
                case COSE_ES256:
                        return "es256";
                case COSE_RS256:
                        return "rs256";
                case COSE_EDDSA:
                        return "eddsa";
                default:
                        return NULL;
        }
}

int fido2_use_hmac_hash(
                const char *device,
                const char *rp_id,
                const void *salt,
                size_t salt_size,
                const void *cid,
                size_t cid_size,
                char **pins,
                Fido2EnrollFlags required, /* client pin/user presence required */
                void **ret_hmac,
                size_t *ret_hmac_size) {

        size_t allocated = 64, found = 0;
        fido_dev_info_t *di = NULL;
        int r;

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 support is not installed.");

        if (device) {
                r = fido2_is_cred_in_specific_token(device, rp_id, cid, cid_size, required);
                if (r == 0)
                        /* The caller is expected to attempt other key slots in this case,
                         * therefore, do not spam the console with error logs here. */
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADSLT),
                                               "The credential is not in the token %s.", device);
                if (r < 0)
                        return log_error_errno(r, "Token returned error during pre-flight: %m");

                return fido2_use_hmac_hash_specific_token(device, rp_id, salt, salt_size, cid, cid_size, pins, required, ret_hmac, ret_hmac_size);
        }

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

                r = fido2_is_cred_in_specific_token(path, rp_id, cid, cid_size, required);
                if (r < 0) {
                        log_error_errno(r, "Token returned error during pre-flight: %m");
                        goto finish;
                }
                if (r == 0) {
                        log_debug("The credential is not in the token %s, skipping.", path);
                        continue;
                }

                r = fido2_use_hmac_hash_specific_token(path, rp_id, salt, salt_size, cid, cid_size, pins, required, ret_hmac, ret_hmac_size);
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

int fido2_generate_hmac_hash(
                const char *device,
                const char *rp_id,
                const char *rp_name,
                const void *user_id, size_t user_id_len,
                const char *user_name,
                const char *user_display_name,
                const char *user_icon,
                const char *askpw_icon,
                const char *askpw_credential,
                Fido2EnrollFlags lock_with,
                int cred_alg,
                const struct iovec *salt,
                void **ret_cid, size_t *ret_cid_size,
                void **ret_secret, size_t *ret_secret_size,
                char **ret_usedpin,
                Fido2EnrollFlags *ret_locked_with) {

        _cleanup_(erase_and_freep) void *secret_copy = NULL;
        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        _cleanup_(fido_cred_free_wrapper) fido_cred_t *c = NULL;
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        _cleanup_(erase_and_freep) char *used_pin = NULL;
        bool has_rk, has_client_pin, has_up, has_uv, has_always_uv;
        _cleanup_free_ char *cid_copy = NULL;
        size_t cid_size, secret_size;
        const void *cid, *secret;
        int r;

        assert(device);
        assert(ret_cid);
        assert(ret_cid_size);
        assert(ret_secret);
        assert(ret_secret_size);

        /* Construction is like this: we read or generate a salt of 32 bytes. We then ask the FIDO2 device to
         * HMAC-SHA256 it for us with its internal key. The result is the key used by LUKS and account
         * authentication. LUKS and UNIX password auth all do their own salting before hashing, so that FIDO2
         * device never sees the volume key.
         *
         * S = HMAC-SHA256(I, D)
         *
         * with: S → LUKS/account authentication key                                         (never stored)
         *       I → internal key on FIDO2 device                              (stored in the FIDO2 device)
         *       D → salt     (stored in the privileged part of the JSON record or read from a file/socket)
         *
         */

        assert(device);
        assert((lock_with & ~(FIDO2ENROLL_PIN|FIDO2ENROLL_UP|FIDO2ENROLL_UV)) == 0);
        assert(iovec_is_set(salt));

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 token support is not installed.");

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, device);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", device, sym_fido_strerr(r));

        r = verify_features(d, device, LOG_ERR, &has_rk, &has_client_pin, &has_up, &has_uv, &has_always_uv);
        if (r < 0)
                return r;

        /* While enrolling degrade gracefully if the requested feature set isn't available, but let the user know */
        if (!has_client_pin && FLAGS_SET(lock_with, FIDO2ENROLL_PIN)) {
                log_notice("Requested to lock with PIN, but FIDO2 device %s does not support it, disabling.", device);
                lock_with &= ~FIDO2ENROLL_PIN;
        }

        if (!has_up && FLAGS_SET(lock_with, FIDO2ENROLL_UP)) {
                log_notice("Locking with user presence test requested, but FIDO2 device %s does not support it, disabling.", device);
                lock_with &= ~FIDO2ENROLL_UP;
        }

        if (!has_uv && FLAGS_SET(lock_with, FIDO2ENROLL_UV)) {
                log_notice("Locking with user verification test requested, but FIDO2 device %s does not support it, disabling.", device);
                lock_with &= ~FIDO2ENROLL_UV;
        }

        if (has_always_uv && !(FLAGS_SET(lock_with, FIDO2ENROLL_PIN) || FLAGS_SET(lock_with, FIDO2ENROLL_UV))) {
                if (has_uv) {
                        log_notice("FIDO2 device %s enforces 'always user verification', forcing user verification.", device);
                        lock_with |= FIDO2ENROLL_UV;
                } else if (has_client_pin) {
                        log_notice("FIDO2 device %s enforces 'always user verification', but doesn't support user verification, forcing PIN.", device);
                        lock_with |= FIDO2ENROLL_PIN;
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "FIDO2 device %s enforces 'always user verification', but doesn't support user verification or PIN, cannot proceed.",
                                               device);
        }

        c = sym_fido_cred_new();
        if (!c)
                return log_oom();

        int extensions = FIDO_EXT_HMAC_SECRET;
        if (FLAGS_SET(lock_with, FIDO2ENROLL_UV)) {
                /* Attempt to use the "cred protect" extension, requiring user verification (UV) for this
                 * credential. If the authenticator doesn't support the extension, it will be ignored. */
                extensions |= FIDO_EXT_CRED_PROTECT;

                r = sym_fido_cred_set_prot(c, FIDO_CRED_PROT_UV_REQUIRED);
                if (r != FIDO_OK)
                        log_warning("Failed to set protection level on FIDO2 credential, ignoring: %s", sym_fido_strerr(r));
        }

        r = sym_fido_cred_set_extensions(c, extensions);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to enable extensions on FIDO2 credential: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_rp(c, rp_id, rp_name);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 credential relying party ID/name: %s", sym_fido_strerr(r));

        r = sym_fido_cred_set_type(c, cred_alg);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 credential type to %s: %s", fido2_algorithm_to_string(cred_alg), sym_fido_strerr(r));

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

        /* As per specification "up" is assumed to be implicit when making credentials, hence we don't
         * explicitly enable/disable it here */

        log_info("Initializing FIDO2 credential on security token.");

        if (has_uv || has_up)
                log_notice("%s%s(Hint: This might require confirmation of user presence on security token.)",
                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                           emoji_enabled() ? " " : "");

        /* If we are using the user PIN, then we must pass that PIN to the get_assertion call below, or
         * the authenticator will use the non-user-verification HMAC secret (which differs from the one when
         * the PIN is passed).
         *
         * Rather than potentially trying and failing to create the credential, just collect the PIN first
         * and then pass it to both the make_credential and the get_assertion operations. */
        if (FLAGS_SET(lock_with, FIDO2ENROLL_PIN))
                r = FIDO_ERR_PIN_REQUIRED;
        else
                r = sym_fido_dev_make_cred(d, c, NULL);

        if (r == FIDO_ERR_PIN_REQUIRED) {

                if (!has_client_pin)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Token asks for PIN but doesn't advertise 'clientPin' feature.");

                AskPasswordFlags askpw_flags = ASK_PASSWORD_ACCEPT_CACHED;

                for (;;) {
                        _cleanup_strv_free_erase_ char **pin = NULL;
                        AskPasswordRequest req = {
                                .tty_fd = -EBADF,
                                .message = "Please enter security token PIN:",
                                .icon = askpw_icon,
                                .keyring = "fido2-pin",
                                .credential = askpw_credential,
                                .until = USEC_INFINITY,
                                .hup_fd = -EBADF,
                        };

                        r = ask_password_auto(&req, askpw_flags, &pin);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire user PIN: %m");

                        askpw_flags &= ~ASK_PASSWORD_ACCEPT_CACHED;

                        r = FIDO_ERR_PIN_INVALID;
                        STRV_FOREACH(i, pin) {
                                if (isempty(*i)) {
                                        log_notice("PIN may not be empty.");
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
#ifdef FIDO_ERR_UV_BLOCKED
        if (r == FIDO_ERR_UV_BLOCKED)
                return log_notice_errno(SYNTHETIC_ERRNO(EPERM),
                                        "Token verification is currently blocked, please remove and reinsert token.");
#endif
        if (r == FIDO_ERR_ACTION_TIMEOUT)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSTR),
                                       "Token action timeout. (User didn't interact with token quickly enough.)");
        if (r == FIDO_ERR_UNSUPPORTED_ALGORITHM)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Token doesn't support credential algorithm %s.", fido2_algorithm_to_string(cred_alg));
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

        r = sym_fido_assert_set_hmac_salt(a, salt->iov_base, salt->iov_len);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set salt on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = fido2_assert_set_basic_properties(a, rp_id, cid, cid_size);
        if (r < 0)
                return r;

        log_info("Generating secret key on FIDO2 security token.");

        if (has_up) {
                r = sym_fido_assert_set_up(a, FLAGS_SET(lock_with, FIDO2ENROLL_UP) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to %s FIDO2 user presence test: %s",
                                               enable_disable(FLAGS_SET(lock_with, FIDO2ENROLL_UP)),
                                               sym_fido_strerr(r));

                if (FLAGS_SET(lock_with, FIDO2ENROLL_UP))
                        log_notice("%s%sIn order to allow secret key generation, please confirm presence on security token.",
                                   emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                   emoji_enabled() ? " " : "");
        }

        if (has_uv) {
                r = sym_fido_assert_set_uv(a, FLAGS_SET(lock_with, FIDO2ENROLL_UV) ? FIDO_OPT_TRUE : FIDO_OPT_FALSE);
                if (r != FIDO_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to %s FIDO user verification: %s",
                                               enable_disable(FLAGS_SET(lock_with, FIDO2ENROLL_UV)),
                                               sym_fido_strerr(r));

                if (FLAGS_SET(lock_with, FIDO2ENROLL_UV))
                        log_notice("%s%sIn order to allow secret key generation, please verify user on security token.",
                                   emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                   emoji_enabled() ? " " : "");
        }

        for (;;) {
                bool retry_with_up = false, retry_with_pin = false;

                r = sym_fido_dev_get_assert(d, a, FLAGS_SET(lock_with, FIDO2ENROLL_PIN) ? used_pin : NULL);

                switch (r) {

                case FIDO_ERR_UP_REQUIRED:
                        /* If the token asks for "up" when we turn off, then this might be a feature that
                         * isn't optional. Let's enable it */

                        if (!has_up)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for user presence test but doesn't advertise 'up' feature.");

                        if (FLAGS_SET(lock_with, FIDO2ENROLL_UP))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for user presence test but was already enabled.");

                        log_notice("%s%sLocking without user presence test requested, but FIDO2 device %s requires it, enabling.",
                                   emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                   emoji_enabled() ? " " : "",
                                   device);

                        retry_with_up = true;
                        break;

                case FIDO_ERR_UNSUPPORTED_OPTION:
                        /* AuthenTrend ATKey.Pro says it supports "up", but if we disable it it will fail
                         * with FIDO_ERR_UNSUPPORTED_OPTION, probably because it isn't actually
                         * optional. Let's see if turning it on works. This is very similar to the
                         * FIDO_ERR_UP_REQUIRED case, but since the error is so vague we implement it
                         * slightly more defensively. */

                        if (has_up && !FLAGS_SET(lock_with, FIDO2ENROLL_UP)) {
                                log_notice("%s%sGot unsupported option error when user presence test is turned off. Trying with user presence test turned on.",
                                           emoji_enabled() ? glyph(GLYPH_TOUCH) : "",
                                           emoji_enabled() ? " " : "");
                                retry_with_up = true;
                        }

                        break;

                case FIDO_ERR_PIN_REQUIRED:
                        if (!has_client_pin)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for client PIN check but doesn't advertise 'clientPin' feature.");

                        if (FLAGS_SET(lock_with, FIDO2ENROLL_PIN))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Token asks for user client PIN check but was already enabled.");

                        log_debug("Token requires PIN for assertion, enabling.");
                        retry_with_pin = true;
                        break;

                default:
                        ;
                }

                if (!retry_with_up && !retry_with_pin)
                        break;

                if (retry_with_up) {
                        r = sym_fido_assert_set_up(a, FIDO_OPT_TRUE);
                        if (r != FIDO_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to enable FIDO2 user presence test: %s", sym_fido_strerr(r));

                        lock_with |= FIDO2ENROLL_UP;
                }

                if (retry_with_pin)
                        lock_with |= FIDO2ENROLL_PIN;
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
        *ret_secret = TAKE_PTR(secret_copy);
        *ret_secret_size = secret_size;

        if (ret_usedpin)
                *ret_usedpin = TAKE_PTR(used_pin);

        if (ret_locked_with)
                *ret_locked_with = lock_with;

        return 0;
}
#endif

#if HAVE_LIBFIDO2
static int check_device_is_fido2_with_hmac_secret(
                const char *path,
                bool *ret_has_rk,
                bool *ret_has_client_pin,
                bool *ret_has_up,
                bool *ret_has_uv,
                bool *ret_has_always_uv) {

        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        int r;

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, path);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", path, sym_fido_strerr(r));

        r = verify_features(d, path, LOG_DEBUG, ret_has_rk, ret_has_client_pin, ret_has_up, ret_has_uv, ret_has_always_uv);
        if (r == -ENODEV) { /* Not a FIDO2 device, or not implementing 'hmac-secret' */
                *ret_has_rk = *ret_has_client_pin = *ret_has_up = *ret_has_uv = *ret_has_always_uv = false;
                return false;
        }
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

        t = table_new("path", "manufacturer", "product", "compatible", "rk", "clientpin", "up", "uv", "alwaysuv");
        if (!t) {
                r = log_oom();
                goto finish;
        }

        for (size_t i = 0; i < found; i++) {
                const fido_dev_info_t *entry;
                bool has_rk, has_client_pin, has_up, has_uv, has_always_uv;

                entry = sym_fido_dev_info_ptr(di, i);
                if (!entry) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO),
                                            "Failed to get device information for FIDO device %zu.", i);
                        goto finish;
                }

                r = check_device_is_fido2_with_hmac_secret(sym_fido_dev_info_path(entry), &has_rk, &has_client_pin, &has_up, &has_uv, &has_always_uv);
                if (r < 0)
                        goto finish;
                bool compatible = r > 0;

                r = table_add_many(
                                t,
                                TABLE_PATH, sym_fido_dev_info_path(entry),
                                TABLE_STRING, sym_fido_dev_info_manufacturer_string(entry),
                                TABLE_STRING, sym_fido_dev_info_product_string(entry),
                                TABLE_BOOLEAN_CHECKMARK, compatible,
                                TABLE_BOOLEAN_CHECKMARK, has_rk,
                                TABLE_BOOLEAN_CHECKMARK, has_client_pin,
                                TABLE_BOOLEAN_CHECKMARK, has_up,
                                TABLE_BOOLEAN_CHECKMARK, has_uv,
                                TABLE_BOOLEAN_CHECKMARK, has_always_uv);
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

        if (table_get_rows(t) > 1)
                printf("\n"
                       "%1$sLegend: RK        %2$s Resident key%3$s\n"
                       "%1$s        CLIENTPIN %2$s PIN request%3$s\n"
                       "%1$s        UP        %2$s User presence%3$s\n"
                       "%1$s        UV        %2$s User verification%3$s\n"
                       "%1$s        AlwaysUV  %2$s User verification Required%3$s\n",
                       ansi_grey(),
                       glyph(GLYPH_ARROW_RIGHT),
                       ansi_normal());

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

        r = check_device_is_fido2_with_hmac_secret(
                        sym_fido_dev_info_path(entry),
                        /* ret_has_rk= */ NULL,
                        /* ret_has_client_pin= */ NULL,
                        /* ret_has_up= */ NULL,
                        /* ret_has_uv= */ NULL,
                        /* ret_has_always_uv= */ NULL);
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

int fido2_have_device(const char *device) {
#if HAVE_LIBFIDO2
        size_t allocated = 64, found = 0;
        fido_dev_info_t *di = NULL;
        int r;

        /* Return == 0 if not devices are found, > 0 if at least one is found */

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 support is not installed.");

        if (device) {
                if (access(device, F_OK) < 0) {
                        if (errno == ENOENT)
                                return 0;

                        return log_error_errno(errno, "Failed to determine whether device '%s' exists: %m", device);
                }

                return 1;
        }

        di = sym_fido_dev_info_new(allocated);
        if (!di)
                return log_oom();

        r = sym_fido_dev_info_manifest(di, allocated, &found);
        if (r == FIDO_ERR_INTERNAL) {
                /* The library returns FIDO_ERR_INTERNAL when no devices are found. I wish it wouldn't. */
                r = 0;
                goto finish;
        }
        if (r != FIDO_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to enumerate FIDO2 devices: %s", sym_fido_strerr(r));
                goto finish;
        }

        r = found;

finish:
        sym_fido_dev_info_free(&di, allocated);
        return r;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                               "FIDO2 tokens not supported on this build.");
#endif
}

#if HAVE_LIBFIDO2
int parse_fido2_algorithm(const char *s, int *ret) {
        int a;

        assert(s);

        if (streq(s, "es256"))
                a = COSE_ES256;
        else if (streq(s, "rs256"))
                a = COSE_RS256;
        else if (streq(s, "eddsa"))
                a = COSE_EDDSA;
        else
                return -EINVAL;

        if (ret)
                *ret = a;
        return 0;
}
#endif
