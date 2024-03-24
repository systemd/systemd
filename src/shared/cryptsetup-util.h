/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "json.h"
#include "macro.h"

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

/* These next two are defined in libcryptsetup.h from cryptsetup version 2.3.4 forwards. */
#ifndef CRYPT_ACTIVATE_NO_READ_WORKQUEUE
#define CRYPT_ACTIVATE_NO_READ_WORKQUEUE (1 << 24)
#endif
#ifndef CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE
#define CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE (1 << 25)
#endif

DLSYM_PROTOTYPE(crypt_activate_by_passphrase);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
DLSYM_PROTOTYPE(crypt_activate_by_signed_key);
#endif
DLSYM_PROTOTYPE(crypt_activate_by_volume_key);
DLSYM_PROTOTYPE(crypt_deactivate_by_name);
DLSYM_PROTOTYPE(crypt_format);
DLSYM_PROTOTYPE(crypt_free);
DLSYM_PROTOTYPE(crypt_get_cipher);
DLSYM_PROTOTYPE(crypt_get_cipher_mode);
DLSYM_PROTOTYPE(crypt_get_data_offset);
DLSYM_PROTOTYPE(crypt_get_device_name);
DLSYM_PROTOTYPE(crypt_get_dir);
DLSYM_PROTOTYPE(crypt_get_type);
DLSYM_PROTOTYPE(crypt_get_uuid);
DLSYM_PROTOTYPE(crypt_get_verity_info);
DLSYM_PROTOTYPE(crypt_get_volume_key_size);
DLSYM_PROTOTYPE(crypt_init);
DLSYM_PROTOTYPE(crypt_init_by_name);
DLSYM_PROTOTYPE(crypt_keyslot_add_by_volume_key);
DLSYM_PROTOTYPE(crypt_keyslot_destroy);
DLSYM_PROTOTYPE(crypt_keyslot_max);
DLSYM_PROTOTYPE(crypt_load);
DLSYM_PROTOTYPE(crypt_resize);
#if HAVE_CRYPT_RESUME_BY_VOLUME_KEY
DLSYM_PROTOTYPE(crypt_resume_by_volume_key);
#endif
DLSYM_PROTOTYPE(crypt_set_data_device);
DLSYM_PROTOTYPE(crypt_set_debug_level);
DLSYM_PROTOTYPE(crypt_set_log_callback);
#if HAVE_CRYPT_SET_METADATA_SIZE
DLSYM_PROTOTYPE(crypt_set_metadata_size);
#endif
DLSYM_PROTOTYPE(crypt_set_pbkdf_type);
DLSYM_PROTOTYPE(crypt_suspend);
DLSYM_PROTOTYPE(crypt_token_json_get);
DLSYM_PROTOTYPE(crypt_token_json_set);
#if HAVE_CRYPT_TOKEN_MAX
DLSYM_PROTOTYPE(crypt_token_max);
#else
/* As a fallback, use the same hard-coded value libcryptsetup uses internally. */
static inline int crypt_token_max(_unused_ const char *type) {
    assert(streq(type, CRYPT_LUKS2));

    return 32;
}
#define sym_crypt_token_max(type) crypt_token_max(type)
#endif
DLSYM_PROTOTYPE(crypt_token_status);
DLSYM_PROTOTYPE(crypt_volume_key_get);
#if HAVE_CRYPT_REENCRYPT_INIT_BY_PASSPHRASE
DLSYM_PROTOTYPE(crypt_reencrypt_init_by_passphrase);
#endif
#if HAVE_CRYPT_REENCRYPT
DISABLE_WARNING_DEPRECATED_DECLARATIONS;
DLSYM_PROTOTYPE(crypt_reencrypt);
REENABLE_WARNING;
#endif
DLSYM_PROTOTYPE(crypt_metadata_locking);
#if HAVE_CRYPT_SET_DATA_OFFSET
DLSYM_PROTOTYPE(crypt_set_data_offset);
#endif
DLSYM_PROTOTYPE(crypt_header_restore);
DLSYM_PROTOTYPE(crypt_volume_key_keyring);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, crypt_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, sym_crypt_free, NULL);

/* Be careful, this works with dlopen_cryptsetup(), that is, it calls sym_crypt_free() instead of crypt_free(). */
#define crypt_free_and_replace(a, b)                    \
        free_and_replace_full(a, b, sym_crypt_free)

void cryptsetup_enable_logging(struct crypt_device *cd);

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd);

int cryptsetup_get_token_as_json(struct crypt_device *cd, int idx, const char *verify_type, JsonVariant **ret);
int cryptsetup_add_token_json(struct crypt_device *cd, JsonVariant *v);

#else

/* If libcryptsetup is not available, let's at least define the basic type and NOP destructors for it, to
 * make a little bit less #ifdeferry necessary in main programs. */
struct crypt_device;
static inline void sym_crypt_free(struct crypt_device* cd) {}
static inline void sym_crypt_freep(struct crypt_device** cd) {}

#endif

int dlopen_cryptsetup(void);

int cryptsetup_get_keyslot_from_token(JsonVariant *v);

static inline const char *mangle_none(const char *s) {
        /* A helper that turns cryptsetup/integritysetup/veritysetup "options" strings into NULL if they are effectively empty */
        return isempty(s) || STR_IN_SET(s, "-", "none") ? NULL : s;
}
