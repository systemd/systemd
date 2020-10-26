/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_LIBCRYPTSETUP
#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "cryptsetup-wrapper.h"
#include "dlfcn-util.h"
#include "log.h"

static void *cryptsetup_dl = NULL;

wrap_type_crypt_activate_by_passphrase sym_crypt_activate_by_passphrase;
wrap_type_crypt_activate_by_volume_key sym_crypt_activate_by_volume_key;
wrap_type_crypt_deactivate_by_name sym_crypt_deactivate_by_name;
wrap_type_crypt_free sym_crypt_free;
wrap_type_crypt_format sym_crypt_format;
wrap_type_crypt_get_dir sym_crypt_get_dir;
wrap_type_crypt_get_verity_info sym_crypt_get_verity_info;
wrap_type_crypt_init sym_crypt_init;
wrap_type_crypt_init_by_name sym_crypt_init_by_name;
wrap_type_crypt_keyslot_add_by_volume_key sym_crypt_keyslot_add_by_volume_key;
wrap_type_crypt_load sym_crypt_load;
wrap_type_crypt_resize sym_crypt_resize;
wrap_type_crypt_set_data_device sym_crypt_set_data_device;
wrap_type_crypt_set_debug_level sym_crypt_set_debug_level;
wrap_type_crypt_set_log_callback sym_crypt_set_log_callback;
wrap_type_crypt_volume_key_get sym_crypt_volume_key_get;
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
wrap_type_crypt_activate_by_signed_key sym_crypt_activate_by_signed_key;
#endif

int dlopen_cryptsetup(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (cryptsetup_dl)
                return 0; /* Already loaded */

        dl = dlopen("libcryptsetup-wrapper.so", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libcryptsetup support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        &sym_crypt_activate_by_passphrase,    "wrap_crypt_activate_by_passphrase",
                        &sym_crypt_activate_by_volume_key,    "wrap_crypt_activate_by_volume_key",
                        &sym_crypt_deactivate_by_name,        "wrap_crypt_deactivate_by_name",
                        &sym_crypt_format,                    "wrap_crypt_format",
                        &sym_crypt_free,                      "wrap_crypt_free",
                        &sym_crypt_get_dir,                   "wrap_crypt_get_dir",
                        &sym_crypt_get_verity_info,           "wrap_crypt_get_verity_info",
                        &sym_crypt_init,                      "wrap_crypt_init",
                        &sym_crypt_init_by_name,              "wrap_crypt_init_by_name",
                        &sym_crypt_keyslot_add_by_volume_key, "wrap_crypt_keyslot_add_by_volume_key",
                        &sym_crypt_load,                      "wrap_crypt_load",
                        &sym_crypt_resize,                    "wrap_crypt_resize",
                        &sym_crypt_set_data_device,           "wrap_crypt_set_data_device",
                        &sym_crypt_set_debug_level,           "wrap_crypt_set_debug_level",
                        &sym_crypt_set_log_callback,          "wrap_crypt_set_log_callback",
                        &sym_crypt_volume_key_get,            "wrap_crypt_volume_key_get",
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        &sym_crypt_activate_by_signed_key,    "wrap_crypt_activate_by_signed_key",
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

#endif
