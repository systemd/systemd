/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "alloc-util.h"
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
extern const char *(*sym_crypt_get_cipher)(struct crypt_device *cd);
extern const char *(*sym_crypt_get_cipher_mode)(struct crypt_device *cd);
extern uint64_t (*sym_crypt_get_data_offset)(struct crypt_device *cd);
extern const char *(*sym_crypt_get_device_name)(struct crypt_device *cd);
extern const char *(*sym_crypt_get_dir)(void);
extern const char *(*sym_crypt_get_type)(struct crypt_device *cd);
extern const char *(*sym_crypt_get_uuid)(struct crypt_device *cd);
extern int (*sym_crypt_get_verity_info)(struct crypt_device *cd, struct crypt_params_verity *vp);
extern int (*sym_crypt_get_volume_key_size)(struct crypt_device *cd);
extern int (*sym_crypt_init)(struct crypt_device **cd, const char *device);
extern int (*sym_crypt_init_by_name)(struct crypt_device **cd, const char *name);
extern int (*sym_crypt_keyslot_add_by_volume_key)(struct crypt_device *cd, int keyslot, const char *volume_key, size_t volume_key_size, const char *passphrase, size_t passphrase_size);
extern int (*sym_crypt_keyslot_destroy)(struct crypt_device *cd, int keyslot);
extern int (*sym_crypt_keyslot_max)(const char *type);
extern int (*sym_crypt_load)(struct crypt_device *cd, const char *requested_type, void *params);
extern int (*sym_crypt_resize)(struct crypt_device *cd, const char *name, uint64_t new_size);
extern int (*sym_crypt_resume_by_passphrase)(struct crypt_device *cd, const char *name, int keyslot, const char *passphrase, size_t passphrase_size);
extern int (*sym_crypt_set_data_device)(struct crypt_device *cd, const char *device);
extern void (*sym_crypt_set_debug_level)(int level);
extern void (*sym_crypt_set_log_callback)(struct crypt_device *cd, void (*log)(int level, const char *msg, void *usrptr), void *usrptr);
#if HAVE_CRYPT_SET_METADATA_SIZE
extern int (*sym_crypt_set_metadata_size)(struct crypt_device *cd, uint64_t metadata_size, uint64_t keyslots_size);
#endif
extern int (*sym_crypt_set_pbkdf_type)(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf);
extern int (*sym_crypt_suspend)(struct crypt_device *cd, const char *name);
extern int (*sym_crypt_token_json_get)(struct crypt_device *cd, int token, const char **json);
extern int (*sym_crypt_token_json_set)(struct crypt_device *cd, int token, const char *json);
#if HAVE_CRYPT_TOKEN_MAX
extern int (*sym_crypt_token_max)(const char *type);
#else
/* As a fallback, use the same hard-coded value libcryptsetup uses internally. */
static inline int crypt_token_max(_unused_ const char *type) {
    assert(streq(type, CRYPT_LUKS2));

    return 32;
}
#define sym_crypt_token_max(type) crypt_token_max(type)
#endif
extern crypt_token_info (*sym_crypt_token_status)(struct crypt_device *cd, int token, const char **type);
extern int (*sym_crypt_volume_key_get)(struct crypt_device *cd, int keyslot, char *volume_key, size_t *volume_key_size, const char *passphrase, size_t passphrase_size);

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
