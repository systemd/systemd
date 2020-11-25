/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fido.h>

#include "hexdecoct.h"
#include "homework-fido2.h"
#include "libfido2-util.h"
#include "strv.h"

static int fido2_use_specific_token(
                const char *path,
                UserRecord *h,
                UserRecord *secret,
                const Fido2HmacSalt *salt,
                char **ret) {

        _cleanup_(fido_cbor_info_free_wrapper) fido_cbor_info_t *di = NULL;
        _cleanup_(fido_assert_free_wrapper) fido_assert_t *a = NULL;
        _cleanup_(fido_dev_free_wrapper) fido_dev_t *d = NULL;
        bool found_extension = false;
        size_t n, hmac_size;
        const void *hmac;
        char **e;
        int r;

        d = sym_fido_dev_new();
        if (!d)
                return log_oom();

        r = sym_fido_dev_open(d, path);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to open FIDO2 device %s: %s", path, sym_fido_strerr(r));

        if (!sym_fido_dev_is_fido2(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
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

        for (size_t i = 0; i < n; i++)
                if (streq(e[i], "hmac-secret")) {
                        found_extension = true;
                        break;
                }

        if (!found_extension)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV),
                                       "Specified device %s is a FIDO2 device, but does not support the required HMAC-SECRET extension.", path);

        a = sym_fido_assert_new();
        if (!a)
                return log_oom();

        r = sym_fido_assert_set_extensions(a, FIDO_EXT_HMAC_SECRET);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to enable HMAC-SECRET extension on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_hmac_salt(a, salt->salt, salt->salt_size);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set salt on FIDO2 assertion: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_rp(a, "io.systemd.home");
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion ID: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_clientdata_hash(a, (const unsigned char[32]) {}, 32);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion client data hash: %s", sym_fido_strerr(r));

        r = sym_fido_assert_allow_cred(a, salt->credential.id, salt->credential.size);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to add FIDO2 assertion credential ID: %s", sym_fido_strerr(r));

        r = sym_fido_assert_set_up(a, h->fido2_user_presence_permitted <= 0 ? FIDO_OPT_FALSE : FIDO_OPT_TRUE);
        if (r != FIDO_OK)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to set FIDO2 assertion user presence: %s", sym_fido_strerr(r));

        log_info("Asking FIDO2 token for authentication.");

        r = sym_fido_dev_get_assert(d, a, NULL); /* try without pin first */
        if (r == FIDO_ERR_PIN_REQUIRED) {
                char **i;

                /* OK, we needed a pin, try with all pins in turn */
                STRV_FOREACH(i, secret->token_pin) {
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

        r = base64mem(hmac, hmac_size, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to base64 encode HMAC secret: %m");

        return 0;
}

int fido2_use_token(UserRecord *h, UserRecord *secret, const Fido2HmacSalt *salt, char **ret) {
        size_t allocated = 64, found = 0;
        fido_dev_info_t *di = NULL;
        int r;

        r = dlopen_libfido2();
        if (r < 0)
                return log_error_errno(r, "FIDO2 support is not installed.");

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

                r = fido2_use_specific_token(path, h, secret, salt, ret);
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
