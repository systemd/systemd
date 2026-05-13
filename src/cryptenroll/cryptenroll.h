/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

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
        UNLOCK_TPM2,
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

DECLARE_STRING_TABLE_LOOKUP(enroll_type, EnrollType);
DECLARE_STRING_TABLE_LOOKUP(luks2_token_type, EnrollType);
