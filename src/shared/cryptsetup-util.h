/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"
#include "shared-forward.h"

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h> /* IWYU pragma: export */

extern DLSYM_PROTOTYPE(crypt_activate_by_passphrase);
extern DLSYM_PROTOTYPE(crypt_activate_by_signed_key);
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
extern DLSYM_PROTOTYPE(crypt_header_restore);
extern DLSYM_PROTOTYPE(crypt_init);
extern DLSYM_PROTOTYPE(crypt_init_by_name);
extern DLSYM_PROTOTYPE(crypt_keyslot_add_by_volume_key);
extern DLSYM_PROTOTYPE(crypt_keyslot_destroy);
extern DLSYM_PROTOTYPE(crypt_keyslot_max);
extern DLSYM_PROTOTYPE(crypt_load);
extern DLSYM_PROTOTYPE(crypt_metadata_locking);
extern DLSYM_PROTOTYPE(crypt_reencrypt_init_by_passphrase);
extern DLSYM_PROTOTYPE(crypt_reencrypt_run);
extern DLSYM_PROTOTYPE(crypt_resize);
extern DLSYM_PROTOTYPE(crypt_resume_by_volume_key);
extern DLSYM_PROTOTYPE(crypt_set_data_device);
extern DLSYM_PROTOTYPE(crypt_set_data_offset);
extern DLSYM_PROTOTYPE(crypt_set_debug_level);
extern DLSYM_PROTOTYPE(crypt_set_log_callback);
extern DLSYM_PROTOTYPE(crypt_set_metadata_size);
extern DLSYM_PROTOTYPE(crypt_set_pbkdf_type);
extern DLSYM_PROTOTYPE(crypt_suspend);
extern DLSYM_PROTOTYPE(crypt_token_json_get);
extern DLSYM_PROTOTYPE(crypt_token_json_set);
extern DLSYM_PROTOTYPE(crypt_token_max);
#if HAVE_CRYPT_TOKEN_SET_EXTERNAL_PATH
extern DLSYM_PROTOTYPE(crypt_token_set_external_path);
#endif
extern DLSYM_PROTOTYPE(crypt_token_status);
extern DLSYM_PROTOTYPE(crypt_volume_key_get);
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
#endif

int dlopen_cryptsetup(void);

int cryptsetup_get_keyslot_from_token(sd_json_variant *v);

const char* mangle_none(const char *s);
