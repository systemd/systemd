/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

#include "alloc-util.h"
#include "dlfcn-util.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

/* These next two are defined in libcryptsetup.h from cryptsetup version 2.3.4 forwards. */
#ifndef CRYPT_ACTIVATE_NO_READ_WORKQUEUE
#define CRYPT_ACTIVATE_NO_READ_WORKQUEUE (1 << 24)
#endif
#ifndef CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE
#define CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE (1 << 25)
#endif

extern DLSYM_PROTOTYPE(crypt_activate_by_passphrase);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
extern DLSYM_PROTOTYPE(crypt_activate_by_signed_key);
#endif
extern DLSYM_PROTOTYPE(crypt_activate_by_volume_key);
extern DLSYM_PROTOTYPE(crypt_deactivate_by_name);
extern DLSYM_PROTOTYPE(crypt_format);
extern DLSYM_PROTOTYPE(crypt_free);
extern DLSYM_PROTOTYPE(crypt_get_cipher);
extern DLSYM_PROTOTYPE(crypt_get_cipher_mode);
extern DLSYM_PROTOTYPE(crypt_get_data_offset);
extern DLSYM_PROTOTYPE(crypt_get_device_name);
extern DLSYM_PROTOTYPE(crypt_get_dir);
extern DLSYM_PROTOTYPE(crypt_get_type);
extern DLSYM_PROTOTYPE(crypt_get_uuid);
extern DLSYM_PROTOTYPE(crypt_get_verity_info);
extern DLSYM_PROTOTYPE(crypt_get_volume_key_size);
extern DLSYM_PROTOTYPE(crypt_init);
extern DLSYM_PROTOTYPE(crypt_init_by_name);
extern DLSYM_PROTOTYPE(crypt_keyslot_add_by_volume_key);
extern DLSYM_PROTOTYPE(crypt_keyslot_destroy);
extern DLSYM_PROTOTYPE(crypt_keyslot_max);
extern DLSYM_PROTOTYPE(crypt_load);
extern DLSYM_PROTOTYPE(crypt_resize);
#if HAVE_CRYPT_RESUME_BY_VOLUME_KEY
extern DLSYM_PROTOTYPE(crypt_resume_by_volume_key);
#endif
extern DLSYM_PROTOTYPE(crypt_set_data_device);
extern DLSYM_PROTOTYPE(crypt_set_debug_level);
extern DLSYM_PROTOTYPE(crypt_set_log_callback);
#if HAVE_CRYPT_SET_METADATA_SIZE
extern DLSYM_PROTOTYPE(crypt_set_metadata_size);
#endif
extern DLSYM_PROTOTYPE(crypt_set_pbkdf_type);
extern DLSYM_PROTOTYPE(crypt_suspend);
extern DLSYM_PROTOTYPE(crypt_token_json_get);
extern DLSYM_PROTOTYPE(crypt_token_json_set);
#if HAVE_CRYPT_TOKEN_MAX
extern DLSYM_PROTOTYPE(crypt_token_max);
#else
/* As a fallback, use the same hard-coded value libcryptsetup uses internally. */
static inline int crypt_token_max(_unused_ const char *type) {
    assert(streq(type, CRYPT_LUKS2));

    return 32;
}
#define sym_crypt_token_max(type) crypt_token_max(type)
#endif
#if HAVE_CRYPT_TOKEN_SET_EXTERNAL_PATH
extern DLSYM_PROTOTYPE(crypt_token_set_external_path);
#endif
extern DLSYM_PROTOTYPE(crypt_token_status);
extern DLSYM_PROTOTYPE(crypt_volume_key_get);
#if HAVE_CRYPT_REENCRYPT_INIT_BY_PASSPHRASE
extern DLSYM_PROTOTYPE(crypt_reencrypt_init_by_passphrase);
#endif
#if HAVE_CRYPT_REENCRYPT_RUN
extern DLSYM_PROTOTYPE(crypt_reencrypt_run);
#elif HAVE_CRYPT_REENCRYPT
extern DLSYM_PROTOTYPE(crypt_reencrypt);
#endif
extern DLSYM_PROTOTYPE(crypt_metadata_locking);
#if HAVE_CRYPT_SET_DATA_OFFSET
extern DLSYM_PROTOTYPE(crypt_set_data_offset);
#endif
extern DLSYM_PROTOTYPE(crypt_header_restore);
extern DLSYM_PROTOTYPE(crypt_volume_key_keyring);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, crypt_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, sym_crypt_free, NULL);

/* Be careful, this works with dlopen_cryptsetup(), that is, it calls sym_crypt_free() instead of crypt_free(). */
#define crypt_free_and_replace(a, b)                    \
        free_and_replace_full(a, b, sym_crypt_free)

void cryptsetup_enable_logging(struct crypt_device *cd);

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd);

int cryptsetup_get_token_as_json(struct crypt_device *cd, int idx, const char *verify_type, sd_json_variant **ret);
int cryptsetup_add_token_json(struct crypt_device *cd, sd_json_variant *v);

#else

/* If libcryptsetup is not available, let's at least define the basic type and NOP destructors for it, to
 * make a little bit less #ifdeferry necessary in main programs. */
struct crypt_device;
static inline void sym_crypt_free(struct crypt_device* cd) {}
static inline void sym_crypt_freep(struct crypt_device** cd) {}

#endif

int dlopen_cryptsetup(void);

int cryptsetup_get_keyslot_from_token(sd_json_variant *v);

static inline const char* mangle_none(const char *s) {
        /* A helper that turns cryptsetup/integritysetup/veritysetup "options" strings into NULL if they are effectively empty */
        return isempty(s) || STR_IN_SET(s, "-", "none") ? NULL : s;
}
