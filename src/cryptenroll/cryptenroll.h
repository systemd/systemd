/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "cryptsetup-util.h"
#include "varlink.h"

typedef enum EnrollType {
        ENROLL_PASSWORD,
        ENROLL_RECOVERY,
        ENROLL_PKCS11,
        ENROLL_FIDO2,
        ENROLL_TPM2,
        _ENROLL_TYPE_MAX,
        _ENROLL_TYPE_INVALID = -EINVAL,
} EnrollType;

typedef enum UnlockType {
        UNLOCK_PASSWORD,
        UNLOCK_KEYFILE,
        UNLOCK_FIDO2,
        _UNLOCK_TYPE_MAX,
        _UNLOCK_TYPE_INVALID = -EINVAL,
} UnlockType;

typedef enum WipeScope {
        WIPE_EXPLICIT,          /* only wipe the listed slots */
        WIPE_ALL,               /* wipe all slots */
        WIPE_EMPTY_PASSPHRASE,  /* wipe slots with empty passphrases plus listed slots */
        _WIPE_SCOPE_MAX,
        _WIPE_SCOPE_INVALID = -EINVAL,
} WipeScope;

const char* enroll_type_to_string(EnrollType t);
EnrollType enroll_type_from_string(const char *s);

const char* luks2_token_type_to_string(EnrollType t);
EnrollType luks2_token_type_from_string(const char *s);

int vl_luks_setup(Varlink *link, JsonVariant *params, struct crypt_device **ret_cd, void **ret_vk, size_t *ret_vks);

/* A set of JsonDispatch initializers that ignore fields used by vl_luks_setup, to avoid complaints
 * about unexpected fields */
#define VARLINK_DISPATCH_UNLOCK_FIELDS                                \
        { .name = "node",           .type = JSON_VARIANT_STRING },    \
        { .name = "unlockPassword", .type = JSON_VARIANT_STRING },    \
        { .name = "unlockKey",      .type = JSON_VARIANT_STRING },    \
        { .name = "unlockFido2",    .type = JSON_VARIANT_STRING }
