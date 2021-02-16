/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

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
extern int (*sym_crypt_set_pbkdf_type)(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf);
extern int (*sym_crypt_token_json_get)(struct crypt_device *cd, int token, const char **json);
extern int (*sym_crypt_token_json_set)(struct crypt_device *cd, int token, const char *json);
extern int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);
#if HAVE_CRYPT_TOKEN_MAX
extern int (*sym_crypt_token_max)(const char *type);
#else
/* As a fallback, use the same hard-coded value libcryptsetup uses internally. */
static inline int sym_crypt_token_max(_unused_ const char *type) {
    assert(streq(type, CRYPT_LUKS2));

    return 32;
}
#endif

int dlopen_cryptsetup(void);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, crypt_free, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct crypt_device *, sym_crypt_free, NULL);

void cryptsetup_enable_logging(struct crypt_device *cd);

int cryptsetup_set_minimal_pbkdf(struct crypt_device *cd);

int cryptsetup_get_token_as_json(struct crypt_device *cd, int idx, const char *verify_type, JsonVariant **ret);
int cryptsetup_get_keyslot_from_token(JsonVariant *v);
int cryptsetup_add_token_json(struct crypt_device *cd, JsonVariant *v);

#endif
