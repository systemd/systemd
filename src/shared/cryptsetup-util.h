/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

extern int (*sym_crypt_activate_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size, uint32_t flags);
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
extern int (*sym_crypt_activate_by_signed_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, const char *signature, size_t signature_size, uint32_t flags);
#endif
extern int (*sym_crypt_activate_by_volume_key)(struct crypt_device *cd, const char *name, const char *volume_key, size_t volume_key_size, uint32_t flags);
extern int (*sym_crypt_deactivate_by_name)(struct crypt_device *cd, const char *name, uint32_t flags);
extern int (*sym_crypt_format)(struct crypt_device *cd, const char *type, const char *cipher, const char *cipher_mode, const char *uuid, const char *volume_key, size_t volume_key_size, void *params);
extern void (*sym_crypt_free)(struct crypt_device *cd);
extern const char *(*sym_crypt_get_dir)(void);
extern int (*sym_crypt_get_verity_info)(struct crypt_device *cd, struct crypt_params_verity *vp);
extern int (*sym_crypt_init)(struct crypt_device **cd, const char *device);
extern int (*sym_crypt_init_by_name)(struct crypt_device **cd, const char *name);
extern int (*sym_crypt_keyslot_add_by_volume_key)(struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
extern int (*sym_crypt_load)(struct crypt_device *cd, const char *requested_type, void *params);
extern int (*sym_crypt_resize)(struct crypt_device *cd, const char *name, uint64_t new_size);
extern int (*sym_crypt_set_data_device)(struct crypt_device *cd, const char *device);
extern void (*sym_crypt_set_debug_level)(int level);
extern void (*sym_crypt_set_log_callback)(struct crypt_device *cd, void (*log)(int level, const char *msg, void *usrptr), void *usrptr);
extern int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);

int dlopen_cryptsetup(void);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct crypt_device *, crypt_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct crypt_device *, sym_crypt_free);

void cryptsetup_enable_logging(struct crypt_device *cd);

#endif
