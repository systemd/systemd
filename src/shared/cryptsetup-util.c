/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBCRYPTSETUP
#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "dlfcn-util.h"
#include "log.h"

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
int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);

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
                        &sym_crypt_activate_by_passphrase, "crypt_activate_by_passphrase",
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        &sym_crypt_activate_by_signed_key, "crypt_activate_by_signed_key",
#endif
                        &sym_crypt_activate_by_volume_key, "crypt_activate_by_volume_key",
                        &sym_crypt_deactivate_by_name, "crypt_deactivate_by_name",
                        &sym_crypt_format, "crypt_format",
                        &sym_crypt_free, "crypt_free",
                        &sym_crypt_get_dir, "crypt_get_dir",
                        &sym_crypt_get_verity_info, "crypt_get_verity_info",
                        &sym_crypt_init, "crypt_init",
                        &sym_crypt_init_by_name, "crypt_init_by_name",
                        &sym_crypt_keyslot_add_by_volume_key, "crypt_keyslot_add_by_volume_key",
                        &sym_crypt_load, "crypt_load",
                        &sym_crypt_resize, "crypt_resize",
                        &sym_crypt_set_data_device, "crypt_set_data_device",
                        &sym_crypt_set_debug_level, "crypt_set_debug_level",
                        &sym_crypt_set_log_callback, "crypt_set_log_callback",
                        &sym_crypt_volume_key_get, "crypt_volume_key_get",
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

#endif
